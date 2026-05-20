import getpass
import os
import re
import sqlite3
import sys
import time
import bcrypt
import pyotp
import qrcode
from auth_db import create_user_record, db_connect, get_user, update_user_field
from logger import generate_ip, log_event

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
PEPPER_FILE = os.path.join(CONFIG_DIR, "auth_pepper.txt")


def enable_mfa(username):
    record = get_user(username)

    if not record:
        print("User does not exist.")
        return

    mfa_secret = record["mfa_secret"]

    if mfa_secret:
        print("\nMFA is already enabled for this user.")
        print("Current secret is:", format_secret(mfa_secret))
        return

    print("\nChoose MFA setup method:")
    print("1. QR Code (recommended)")
    print("2. Manual secret key")

    choice = input("Select option (1 or 2): ").strip()

    while choice not in {"1", "2"}:
        choice = input("Select option (1 or 2): ").strip()

    secret = pyotp.random_base32()

    # NOTE: In production, MFA secrets should be encrypted at rest
    update_user_field(username, "mfa_secret", secret)

    totp = pyotp.TOTP(secret)

    if choice == "1":
        uri = totp.provisioning_uri(name=username, issuer_name="AuthProject")

        QR_DIR = os.path.join(PROJECT_ROOT, "generated_qr")
        os.makedirs(QR_DIR, exist_ok=True)

        img = qrcode.make(uri)
        qr_path = os.path.join(QR_DIR, f"{username}_mfa_qr.png")
        img.save(qr_path)

        print("\nMFA enabled using QR code.")
        print("Scan this QR code with Google Authenticator:")
        print(f"Saved as {qr_path}")

    else:
        print("\nMFA enabled using manual secret.")
        print("Enter this key into Google Authenticator:")
        print(f"Your secret key is: {format_secret(secret)}")
    print("\nMFA setup complete")


def reset_mfa(username):
    record = get_user(username)

    if not record:
        print("User does not exist.")
        return

    print("\n=== MFA Reset Confirmation ===")

    # Step 1: require admin password confirmation
    password = getpass.getpass("Confirm your password: ")
    peppered = password + PEPPER

    stored = record["password"]

    if isinstance(stored, memoryview):
        stored = stored.tobytes()
    elif isinstance(stored, str):
        stored = stored.encode("utf-8")

    if not bcrypt.checkpw(peppered.encode("utf-8"), stored):
        print("Incorrect password. MFA reset denied.")
        log_event(
            "MFA_RESET_FAIL",
            username,
            src_ip=generate_ip(),
            details="wrong_admin_password"
        )
        return

    # Step 2: optional warning for admin accounts
    if record["role"] == "admin":
        print("Warning: Resetting MFA for ADMIN account.")

    # Step 3: reset MFA
    update_user_field(username, "mfa_secret", None)

    src_ip = generate_ip()

    log_event(
        "MFA_RESET",
        username,
        src_ip=src_ip,
        details="mfa_reset_after_password_confirmation"
    )

    print("\nMFA has been reset successfully.")
    print("User will be required to reconfigure MFA on next login.")

def disable_mfa(username):
    record = get_user(username)

    if not record:
        print("Invalid username or password")
        return
    if record["role"] == "admin":
        print("Admin cannot disable MFA.")
        return

    password = getpass.getpass("Re-enter your password: ")
    peppered = password + PEPPER

    stored = record["password"]
    if isinstance(stored, memoryview):
        stored = stored.tobytes()
    elif isinstance(stored, str):
        stored = stored.encode("utf-8")

    src_ip = generate_ip()

    if not bcrypt.checkpw(peppered.encode(), stored):
        print("Password incorrect.")
        log_event("MFA_DISABLE_FAIL", username, src_ip=src_ip, details="wrong_password")
        return

    update_user_field(username, "mfa_secret", None)
    log_event("MFA_DISABLE", username, src_ip=src_ip, details="user_disabled_mfa")
    print("MFA has been disabled.")


def format_secret(secret):
    return " - ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


def looks_malicious(input_string):
    if not isinstance(input_string, str):
        return True

    patterns = [
        r"'",
        r'"',
        r"__",
        r"/\*",
        r"\*/",
        r"\bINSERT\b",
        r"\bAND\b",
        r"\bUNION\b",
        r"\bSELECT\b",
        r"\bOR\b",
        r"\bUPDATE\b",
        r"\bDELETE\b",
        r"\bDROP\b",
        r"\b1=1\b",
    ]

    test = input_string.upper()
    for pattern in patterns:
        if re.search(pattern, test):
            return True

    return False


def validate_username(username):
    if not isinstance(username, str):
        return False

    username = username.strip()

    if len(username) not in range(4, 21):
        return False
    if not username.isalnum():
        return False

    has_letter = any(c.isalpha() for c in username)
    has_digit = any(c.isdigit() for c in username)

    return has_letter and has_digit


def validate_password(password):
    if not isinstance(password, str):
        return False, "Password must be a string"
    if " " in password:
        return False, "Password cannot contain spaces"
    if len(password) not in range(7, 21):
        return False, "Password must be between 7 to 20 characters long"
    if len(set(password)) == 1:
        return False, "Password cannot be made of a single repeating character"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    allowed_symbols = ".@$!%"
    if not any(c in allowed_symbols for c in password):
        return (
            False,
            f"Password must contain at least one special character: {allowed_symbols}",
        )

    return True, None


def load_pepper():
    try:
        with open(PEPPER_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("Error: Pepper file missing!")
    except PermissionError:
        print("Error: Permission denied reading auth_pepper.txt")
    except OSError as e:
        print(f"Error reading pepper file: {e}")
    return None


PEPPER = load_pepper()
if not PEPPER:
    print("Fatal error: authentication pepper not loaded.")
    sys.exit(1)


def create_user():
    username = input("enter a new username: ").strip()
    if looks_malicious(username):
        print("Invalid username. Input rejected for security.")
        log_event(
            "INPUT_REJECT", username, details="suspicious_input_pattern"
        )
        time.sleep(1)
        return
    if not validate_username(username):
        print(
            "Invalid username! Username must be between 4-20 characters long with at least a letter and number"
        )
        time.sleep(1)
        return
    password = getpass.getpass("enter a new password: ")
    confirm = getpass.getpass("Confirm your password: ")
    if password != confirm:
        print("Passwords do not match")
        time.sleep(1)
        return
    valid, msg = validate_password(password)
    if not valid:
        print(msg)
        time.sleep(1)
        return

    peppered = password + PEPPER
    hashed = bcrypt.hashpw(peppered.encode("utf-8"), bcrypt.gensalt())
    try:
        create_user_record(username, hashed)
        print("User created successfully!")
        log_event("USER_REGISTER", username, details="new_user_created")
    except sqlite3.IntegrityError:
        print("Username already exists")
        log_event("USER_REGISTER_FAIL", username, details="username_exists")
        time.sleep(1)


def handle_lockout(username, record):
    current_time = int(time.time())

    if record["locked"] == 1:
        if current_time < record["lockout_until"]:
            cooldown_left = record["lockout_until"] - current_time
            print(f"Try again in {cooldown_left} seconds.")
            log_event("ACCOUNT_LOCKED_ACTIVE", username, details="account_still_locked")
            return False
        else:
            update_user_field(username, "locked", 0)
            update_user_field(username, "failed_attempts", 0)
            update_user_field(username, "lockout_until", 0)

    return True


def check_password(username, password, record, src_ip):
    stored_password = record["password"]

    if isinstance(stored_password, memoryview):
        stored_password = stored_password.tobytes()
    elif isinstance(stored_password, str):
        stored_password = stored_password.encode("utf-8")

    peppered = f"{password}{PEPPER}"
    password_correct = bcrypt.checkpw(peppered.encode("utf-8"), stored_password)

    if not password_correct:
        failed_attempts = record["failed_attempts"] + 1
        update_user_field(username, "failed_attempts", failed_attempts)

        print("Invalid username or password")
        log_event("LOGIN_FAIL", username, src_ip=src_ip, details=f"wrong_password_attempt_{failed_attempts}")

        if failed_attempts >= 3:
            lock_duration = 300
            new_lockout = int(time.time()) + lock_duration
            update_user_field(username, "locked", 1)
            update_user_field(username, "lockout_until", new_lockout)

            print(f"Account locked for {lock_duration} seconds.")
            log_event("ACCOUNT_LOCK", username, src_ip=src_ip, details="too_many_attempts")

        return False

    return True


def handle_mfa(username, record, src_ip):
    role = record["role"]
    mfa_secret = record["mfa_secret"]

    if role == "admin" and not mfa_secret:
        print("Admin has no MFA configured. You must set it up now.")
        enable_mfa(username)

        # reload updated user
        record = get_user(username)
        mfa_secret = record["mfa_secret"]

        if not mfa_secret:
            print("MFA setup failed.")
            return False

    if not mfa_secret:
        return True

    totp = pyotp.TOTP(mfa_secret)
    code = input("Enter 6-digit MFA code: ").strip()

    if not code.isdigit() or len(code) != 6:
        print("Invalid MFA format")
        log_event("MFA_FAIL", username, src_ip=src_ip, details="invalid_format")
        return False

    if not totp.verify(code, valid_window=1):
        print("Incorrect MFA code")
        log_event("MFA_FAIL", username, src_ip=src_ip, details="invalid_mfa_code")
        return False

    print("\nMFA verified")
    log_event("MFA_SUCCESS", username, src_ip=src_ip, details="mfa_verified")
    return True


def login_user():
    try:
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        src_ip = generate_ip()
        if looks_malicious(username) or looks_malicious(password):
            print("Invalid input.")
            log_event("INPUT_REJECT", username, src_ip=src_ip, details="malicious_input")
            return None, None

        record = get_user(username)

        if not record:
            print("Invalid username or password")
            log_event(
                "LOGIN_FAIL",
                username,
                src_ip=src_ip,
                details="unknown_user"
            )
            return None, None

        if not handle_lockout(username, record):
            return None, None

        if not check_password(username, password, record, src_ip):
            return None, None

        if not handle_mfa(username, record, src_ip):
            log_event("LOGIN_FAIL", username, src_ip=src_ip, details="mfa_failed")
            return None, None

        update_user_field(username, "failed_attempts", 0)
        update_user_field(username, "locked", 0)
        update_user_field(username, "lockout_until", 0)

        log_event("LOGIN_SUCCESS", username, src_ip=src_ip)

        return (record["role"], username)

    except Exception as e:
        log_event("ERROR", username if 'username' in locals() else "unknown", details=str(e))
        print("An unexpected error occurred during login.")


def update_password(username):
    print("\n=== Update Password ===")

    oldpass = getpass.getpass("Enter old password: ")

    record = get_user(username)

    if not record:
        print("User not found.")
        return

    password_hash = record["password"]

    if isinstance(password_hash, memoryview):
        password_hash = password_hash.tobytes()
    elif isinstance(password_hash, str):
        password_hash = password_hash.encode("utf-8")

    peppered = oldpass + PEPPER
    password_correct = bcrypt.checkpw(peppered.encode("utf-8"), password_hash)

    if not password_correct:
        print("Incorrect old password")
        return

    newpass = getpass.getpass("Enter new password (leave blank to cancel): ")

    if not newpass:
        log_event("PASSWORD_CHANGE_CANCEL", username)
        return

    valid, msg = validate_password(newpass)
    if not valid:
        print(msg)
        return

    confirm = getpass.getpass("Confirm new password: ")

    if newpass != confirm:
        print("Passwords do not match.")
        return

    peppered_new = newpass + PEPPER
    newpassword = bcrypt.hashpw(peppered_new.encode("utf-8"), bcrypt.gensalt())

    try:
        with db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (newpassword, username),
            )
            conn.commit()

            print("Password successfully updated.")
            log_event("PASSWORD_CHANGE", username, details="password_updated")
    except Exception as e:
        log_event(
            "ERROR",
            username,
            details=f"update_password_failed: {str(e)}"
        )
        print("Password update failed")


def unlock_user():
    print("\n===Which user you want to unlock===")
    target_user = input("Enter the username to unlock: ").strip()

    if looks_malicious(target_user):
        print("Invalid input.")
        log_event(
            "INPUT_REJECT",
            target_user,
            src_ip=generate_ip(),
            details="suspicious_input_pattern"
        )
        return

    user = get_user(target_user)

    if not user:
        print(f"{target_user} does not exist.")
        return

    if not user["locked"]:
        print(f"{target_user} account is not locked")
        return

    update_user_field(target_user, "failed_attempts", 0)
    update_user_field(target_user, "locked", 0)
    update_user_field(target_user, "lockout_until", 0)

    print(f"{target_user}'s account has been unlocked.")
    log_event("ACCOUNT_UNLOCK", target_user, details="unlocked_by_admin")


def login_page(username):
    while True:
        print(f"\n=== User page ({username}) ===")
        print("1. Change Password")
        print("2. Return to Login")
        print("3. Exit")
        print("4. Enable MFA")
        print("5. Disable MFA")
        choice = input("Enter an option: ")

        if choice == "1":
            update_password(username)
        elif choice == "2":
            return "logout"
        elif choice == "3":
            return "exit"
        elif choice == "4":
            enable_mfa(username)
        elif choice == "5":
            disable_mfa(username)
        else:
            print("Invalid option. Try again.")


def admin_page(username):
    while True:
        print(f"\n=== Admin page ({username}) ===")
        print("1. Register new User")
        print("2. Change Password")
        print("3. Unlock User")
        print("4. Return to Login")
        print("5. Reset MFA (force re-enrollment)")
        print("6. Exit")
        choice = input("Enter an option: ")

        if choice == "1":
            create_user()
        elif choice == "2":
            update_password(username)
        elif choice == "3":
            unlock_user()
        elif choice == "4":
            return "logout"
        elif choice == "5":
            target_user = input("Enter username to reset MFA: ").strip()
            reset_mfa(target_user)
        elif choice == "6":
            print("Goodbye!")
            return "exit"
        else:
            print("Invalid option. Try again.")


def main():
    while True:
        print("\n=== Authentication System ===")
        print("=== Login Page ===")
        print("1. Register new user")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter an option: ")

        if choice == "1":
            create_user()
        elif choice == "2":
            role, username = login_user()
            if role is None:
                continue

            if role == "admin":
                result = admin_page(username)
            else:
                result = login_page(username)

            if result == "logout":
                continue
            elif result == "exit":
                sys.exit()
        elif choice == "3":
            print("Goodbye!")
            sys.exit()
        else:
            print("Invalid option. Try again")


if __name__ == "__main__":
    main()
