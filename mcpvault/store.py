"""The encrypted vault file.

On disk:

    {
      "format": "mcp-vault", "version": 1,
      "kdf":  {"name": "scrypt", "n": ..., "r": ..., "p": ..., "salt": ...},
      "key":  {"nonce": ..., "ct": ...},   # DEK wrapped by the password key
      "data": {"nonce": ..., "ct": ...}    # vault JSON encrypted by the DEK
    }
"""

import hmac
import json
import os
import time

from . import crypto, paths

FORMAT = "mcp-vault"
VERSION = 1


class WrongPassword(Exception):
    pass


class VaultLocked(Exception):
    pass


def empty_data() -> dict:
    return {"version": 1, "hosts": [], "servers": [], "settings": {"auto_lock_minutes": 480}}


def atomic_write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    for attempt in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            # Another process may hold the target open briefly (e.g. an MCP client).
            time.sleep(0.2 * (attempt + 1))
    with open(path, "wb") as fh:
        fh.write(data)
    os.remove(tmp)


class Vault:
    def __init__(self, path: str = paths.VAULT_FILE):
        self.path = path
        self._kdf: dict | None = None
        self._wrapped: dict | None = None
        self._dek: bytes | None = None
        self.data: dict | None = None

    # -- state ---------------------------------------------------------------

    def exists(self) -> bool:
        return os.path.exists(self.path)

    @property
    def unlocked(self) -> bool:
        return self._dek is not None

    def require(self) -> dict:
        if self.data is None:
            raise VaultLocked("the vault is locked")
        return self.data

    # -- lifecycle -----------------------------------------------------------

    def create(self, password: str) -> None:
        if self.exists():
            raise FileExistsError("a vault already exists")
        self._kdf = crypto.new_kdf_params()
        kek = crypto.derive_key(password, self._kdf)
        self._dek = os.urandom(32)
        self._wrapped = crypto.seal(kek, self._dek, crypto.aad("key", self._kdf))
        self.data = empty_data()
        self.save()

    def _read_file(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        if obj.get("format") != FORMAT or obj.get("version") != VERSION:
            raise ValueError(f"{self.path} is not an MCP Vault v{VERSION} file")
        return obj

    def _unwrap(self, obj: dict, password: str) -> bytes:
        kek = crypto.derive_key(password, obj["kdf"])
        try:
            return crypto.unseal(kek, obj["key"], crypto.aad("key", obj["kdf"]))
        except crypto.InvalidTag:
            raise WrongPassword("wrong master password") from None

    def unlock(self, password: str) -> None:
        obj = self._read_file()
        dek = self._unwrap(obj, password)
        plaintext = crypto.unseal(dek, obj["data"], crypto.aad("data"))
        data = json.loads(plaintext.decode("utf-8"))
        for key, value in empty_data().items():
            data.setdefault(key, value)
        self._kdf, self._wrapped, self._dek, self.data = obj["kdf"], obj["key"], dek, data

    def verify(self, password: str) -> bool:
        """Check a password against the file without changing state."""
        try:
            dek = self._unwrap(self._read_file(), password)
        except WrongPassword:
            return False
        return self._dek is None or hmac.compare_digest(dek, self._dek)

    def lock(self) -> None:
        self._dek = None
        self.data = None

    def save(self) -> None:
        if self._dek is None or self.data is None:
            raise VaultLocked("the vault is locked")
        plaintext = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
        obj = {
            "format": FORMAT,
            "version": VERSION,
            "kdf": self._kdf,
            "key": self._wrapped,
            "data": crypto.seal(self._dek, plaintext, crypto.aad("data")),
        }
        if os.path.exists(self.path):
            # Keep the previous (still encrypted) generation as a safety net.
            with open(self.path, "rb") as fh:
                atomic_write(self.path + ".prev", fh.read())
        atomic_write(self.path, json.dumps(obj, indent=2).encode("utf-8"))

    def change_password(self, old: str, new: str) -> None:
        if self._dek is None:
            raise VaultLocked("the vault is locked")
        if not self.verify(old):
            raise WrongPassword("the current password is wrong")
        self._kdf = crypto.new_kdf_params()
        kek = crypto.derive_key(new, self._kdf)
        self._wrapped = crypto.seal(kek, self._dek, crypto.aad("key", self._kdf))
        self.save()
        # The .prev copy is wrapped with the old password; drop it.
        try:
            os.remove(self.path + ".prev")
        except OSError:
            pass

    # -- encrypted blobs (backups) ------------------------------------------

    def seal_blob(self, payload: bytes, label: str) -> bytes:
        if self._dek is None:
            raise VaultLocked("the vault is locked")
        return json.dumps(crypto.seal(self._dek, payload, crypto.aad(label))).encode("utf-8")

    def open_blob(self, blob: bytes, label: str) -> bytes:
        if self._dek is None:
            raise VaultLocked("the vault is locked")
        return crypto.unseal(self._dek, json.loads(blob.decode("utf-8")), crypto.aad(label))
