from appconf import AppConf
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from django.conf import settings
from django.utils.encoding import force_bytes


class CryptographyConf(AppConf):
    if not hasattr(settings, 'CRYPTOGRAPHY_BACKEND'):
        BACKEND = default_backend()
    else:
        BACKEND = settings.CRYPTOGRAPHY_BACKEND

    if not hasattr(settings, 'CRYPTOGRAPHY_DIGEST'):
        DIGEST = hashes.SHA256()
    else:
        DIGEST = settings.CRYPTOGRAPHY_DIGEST

    if not hasattr(settings, 'CRYPTOGRAPHY_KEY'):
        KEY = None
    else:
        KEY = settings.CRYPTOGRAPHY_KEY

    if not hasattr(settings, 'CRYPTOGRAPHY_SALT'):
        SALT = 'django-cryptography'
    else:
        SALT = settings.CRYPTOGRAPHY_SALT

    class Meta:
        prefix = 'cryptography'
        proxy = True

    def configure_salt(self, value):
        return force_bytes(value)

    def configure(self):
        backend = self.configured_data['BACKEND']
        digest = self.configured_data['DIGEST']
        salt = self.configured_data['SALT']
        # Key Derivation Function
        kdf = pbkdf2.PBKDF2HMAC(
            algorithm=digest,
            length=digest.digest_size,
            salt=salt,
            iterations=30000,
            backend=backend,
        )
        self.configured_data['KEY'] = kdf.derive(
            force_bytes(self.configured_data['KEY'] or settings.SECRET_KEY)
        )
        return self.configured_data
