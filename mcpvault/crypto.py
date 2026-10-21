"""Key derivation and authenticated encryption.

The vault holds a random 256-bit data key (DEK). The DEK is wrapped with a key
derived from the master password (scrypt), and everything else - the vault
contents and client-config backups - is encrypted with the DEK using
AES-256-GCM. Changing the password only re-wraps the DEK.
"""

import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def new_kdf_params() -> dict:
    return {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": b64e(os.urandom(16))}


def derive_key(password: str, params: dict) -> bytes:
    if params.get("name") != "scrypt":
        raise ValueError(f"unsupported KDF {params.get('name')!r}")
    n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=b64d(params["salt"]),
        n=n, r=r, p=p, dklen=32,
        maxmem=256 * n * r + (32 << 20),
    )


def aad(label: str, extra: dict | None = None) -> bytes:
    """Associated data binding a ciphertext to its purpose (and KDF params)."""
    text = "mcp-vault:" + label
    if extra is not None:
        text += ":" + json.dumps(extra, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def seal(key: bytes, plaintext: bytes, associated: bytes) -> dict:
    nonce = os.urandom(12)
    return {"nonce": b64e(nonce), "ct": b64e(AESGCM(key).encrypt(nonce, plaintext, associated))}


def unseal(key: bytes, box: dict, associated: bytes) -> bytes:
    """Decrypt a sealed box; raises InvalidTag on a wrong key or tampering."""
    return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ct"]), associated)


__all__ = ["InvalidTag", "aad", "b64d", "b64e", "derive_key", "new_kdf_params", "seal", "unseal"]
