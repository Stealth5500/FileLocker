"""
FileLocker - Encrypt and decrypt files with a password.

Usage:
    python file_locker.py lock <file>
    python file_locker.py unlock <file.locked>

Requires: pip install cryptography
"""

import argparse
import base64
import getpass
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- Security parameters ---------------------------------------------------
# Salt is random per-file, so two files encrypted with the same password
# still produce unrelated ciphertext.
SALT_SIZE = 16

# Number of PBKDF2 rounds. Higher = slower brute-force for an attacker, but
# also slower for the legitimate user. See README "Common Issues".
ITERATIONS = 200_000

# Fixed bytes at the start of every locked file. Used to fail fast when the
# user tries to "unlock" something that was never locked by this tool.
MAGIC_HEADER = b"LOCKEDv1"


def derive_key(password, salt):
    """Derive a 32-byte key from the password using PBKDF2-HMAC-SHA256.

    Fernet expects a URL-safe base64-encoded 32-byte key, so we encode the
    raw KDF output before returning it.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def lock_file(input_path, password, output_path=None):
    """Encrypt a file. Output layout: [HEADER][SALT][Fernet ciphertext]."""
    if not input_path.is_file():
        raise FileNotFoundError("File not found: " + str(input_path))

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".locked")

    # os.urandom is the OS-provided cryptographically secure random source.
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    # Read the whole file into memory. Fine for typical documents but not
    # for multi-GB files - see "Common Issues" in the README.
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Fernet handles IV/nonce, AES-128-CBC, and HMAC-SHA256 in one call.
    ciphertext = fernet.encrypt(plaintext)

    with open(output_path, "wb") as f:
        f.write(MAGIC_HEADER)
        f.write(salt)
        f.write(ciphertext)

    return output_path


def unlock_file(input_path, password, output_path=None):
    """Decrypt a previously locked file."""
    if not input_path.is_file():
        raise FileNotFoundError("File not found: " + str(input_path))

    with open(input_path, "rb") as f:
        # Reject non-locked files before we try to decrypt anything.
        header = f.read(len(MAGIC_HEADER))
        if header != MAGIC_HEADER:
            raise ValueError("Not a valid locked file (header mismatch).")
        salt = f.read(SALT_SIZE)
        ciphertext = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        # Fernet does not distinguish "wrong password" from "tampered data".
        # Both produce InvalidToken because HMAC verification fails.
        raise ValueError("Wrong password or file is corrupted.")

    if output_path is None:
        if input_path.suffix == ".locked":
            output_path = input_path.with_suffix("")
        else:
            output_path = input_path.with_name(input_path.stem + ".unlocked")
        # Avoid silently overwriting an existing file.
        if output_path.exists():
            output_path = output_path.with_name(
                output_path.stem + "_unlocked" + output_path.suffix
            )

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return output_path


def prompt_password(confirm=False):
    """Read a password without echoing it to the terminal.

    getpass disables echo so the password is not visible while typing or
    left in scrollback. We confirm at lock time because a typo means the
    file is unrecoverable.
    """
    pwd = getpass.getpass("Enter password: ")
    if not pwd:
        raise ValueError("Password cannot be empty.")
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            raise ValueError("Passwords do not match.")
    return pwd


def main():
    parser = argparse.ArgumentParser(
        description="FileLocker - encrypt and decrypt files with a password.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_lock = sub.add_parser("lock", help="Encrypt a file with a password")
    p_lock.add_argument("file", type=Path)
    p_lock.add_argument("-o", "--output", type=Path, default=None)

    p_unlock = sub.add_parser("unlock", help="Decrypt a locked file")
    p_unlock.add_argument("file", type=Path)
    p_unlock.add_argument("-o", "--output", type=Path, default=None)

    args = parser.parse_args()

    try:
        if args.command == "lock":
            password = prompt_password(confirm=True)
            out = lock_file(args.file, password, args.output)
            print("[OK] File locked: " + str(out))
        elif args.command == "unlock":
            password = prompt_password(confirm=False)
            out = unlock_file(args.file, password, args.output)
            print("[OK] File unlocked: " + str(out))
    except (FileNotFoundError, ValueError) as e:
        # Recoverable errors: print to stderr, exit non-zero so shell
        # scripts can detect failure.
        print("[ERROR] " + str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[Cancelled by user]", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
