"""
hooks/cli.py
------------
Developer-facing CLI for CloudSentinel authentication.
This is the ONLY place interactive login happens - never inside the hook.

Usage:
    python -m hooks.cli login
    python -m hooks.cli status
"""

import getpass
import sys

from hooks import api_client
from hooks.config import TOKEN_FILE


def cmd_login():
    print()
    print("  [*] CloudSentinel - Authentication")
    print("  " + "-" * 40)
    print()
    email = input("  Email    : ").strip()
    password = getpass.getpass("  Password : ")
    print()
    print("  Authenticating...")

    token = api_client.authenticate(email, password)
    if token:
        api_client.save_token(token)
        print(f"  [OK] Authenticated successfully.")
        print(f"  [OK] Token saved to: {TOKEN_FILE}")
        print()
    else:
        print("  [X]  Authentication failed. Check your email, password, and that")
        print("       the CloudSentinel backend is running at the configured URL.")
        print()
        sys.exit(1)


def cmd_status():
    token = api_client.load_token()
    if token:
        print(f"\n  [OK] Token found at {TOKEN_FILE}")
        print(f"  [OK] Value: {token[:8]}...{token[-4:]}")
    else:
        print(f"\n  [X]  No token found. Run: python -m hooks.cli login")
    print()


def main():
    if len(sys.argv) < 2:
        print("\n  Usage: python -m hooks.cli [login|status]\n")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "login":
        cmd_login()
    elif cmd == "status":
        cmd_status()
    else:
        print(f"\n  Unknown command: {cmd}")
        print("  Usage: python -m hooks.cli [login|status]\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
