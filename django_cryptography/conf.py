from typing import Any, Dict

from appconf import AppConf
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from django.conf import settings
from django.utils.encoding import force_bytes


class CryptographyConf(AppConf):
    BACKEND = default_backend()
    DIGEST = hashes.SHA256()
    KEY = None
    SALT = "django-cryptography"

    class Meta:
        prefix = "cryptography"
        proxy = True

    def configure_salt(self, value: Any) -> bytes:
        return force_bytes(value)

    def configure(self) -> Dict[str, Any]:
        backend = self.configured_data["BACKEND"]
        digest = self.configured_data["DIGEST"]
        salt = self.configured_data["SALT"]
        # Key Derivation Function
        kdf = pbkdf2.PBKDF2HMAC(
            algorithm=digest,
            length=digest.digest_size,
            salt=salt,
            iterations=30000,
            backend=backend,
        )
        self.configured_data["KEY"] = kdf.derive(
            force_bytes(self.configured_data["KEY"] or settings.SECRET_KEY)
        )
        return self.configured_data
