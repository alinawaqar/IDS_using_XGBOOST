"""
Run this once to generate the value for IDS_PASSWORD_HASH.

    python hash_password.py

It prompts for your password (input is hidden) and prints a bcrypt hash.
Paste that hash into your environment as IDS_PASSWORD_HASH -- never store
the plaintext password itself anywhere.
"""

import getpass
from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

if __name__ == "__main__":
    pw = getpass.getpass("Choose a password: ")
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        raise SystemExit("Passwords didn't match.")
    print("\nSet this as IDS_PASSWORD_HASH:\n")
    print(pwd_ctx.hash(pw))