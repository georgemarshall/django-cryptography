import base64
import os
from binascii import Error

from cryptography.hazmat.primitives import constant_time, hashes, padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.utils import crypto
from django.utils.encoding import force_bytes

from ..conf import CryptographyConf

settings = CryptographyConf()


class InvalidToken(Exception):
    pass


def salted_hmac(salt, value, secret=None):
    """
    Returns the HMAC-HASH of 'value', using a key generated from salt and a
    secret (which defaults to settings.CRYPTOGRAPHY_SIGNINGKEY).

    A different salt should be passed in for every application of HMAC.

    :type salt: any
    :type value: any
    :type secret: any
    :rtype: HMAC
    """

    salt = force_bytes(salt)
    secret = force_bytes(secret or settings.CRYPTOGRAPHY_SIGNINGKEY)

    # We need to generate a derived key from our base key.  We can do this by
    # passing the salt and our base key through a pseudo-random function and
    # SHA1 works nicely.
    digest = hashes.Hash(settings.CRYPTOGRAPHY_DIGEST,
                         backend=settings.CRYPTOGRAPHY_BACKEND)
    digest.update(salt + secret)
    key = digest.finalize()

    # If len(key_salt + secret) > sha_constructor().block_size, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.
    h = HMAC(key, settings.CRYPTOGRAPHY_DIGEST,
             backend=settings.CRYPTOGRAPHY_BACKEND)
    h.update(force_bytes(value))
    return h


get_random_string = crypto.get_random_string


def constant_time_compare(val1, val2):
    """
    :type val1: any
    :type val2: any
    :rtype: bool
    """
    return constant_time.bytes_eq(force_bytes(val1), force_bytes(val2))


def pbkdf2(password, salt, iterations, dklen=0, digest=None):
    """
    Implements PBKDF2 with the same API as Django's existing
    implementation, using cryptography.

    :type password: any
    :type salt: any
    :type iterations: int
    :type dklen: int
    :type digest: cryptography.hazmat.primitives.hashes.HashAlgorithm
    """
    if digest is None:
        digest = settings.CRYPTOGRAPHY_DIGEST
    if not dklen:
        dklen = digest.digest_size
    password = force_bytes(password)
    salt = force_bytes(salt)
    kdf = PBKDF2HMAC(
        algorithm=digest, length=dklen, salt=salt,
        iterations=iterations, backend=settings.CRYPTOGRAPHY_BACKEND
    )
    return kdf.derive(password)


class FernetBytes(object):
    """
    This is a modified version of the Fernet encryption algorithm from
    the Python Cryptography library. The main change is the allowance
    of varied length cryptographic keys from the base 128-bit. There is
    also an emphasis on using Django's settings system for sane defaults.
    """

    def __init__(self, key=None, signer=None):
        self._backend = settings.CRYPTOGRAPHY_BACKEND
        self._encryption_key = force_bytes(key or settings.CRYPTOGRAPHY_KEY)
        if signer is None:
            from ..core.signing import FernetSigner
            signer = FernetSigner()
        self._signer = signer

    def encrypt(self, data):
        """
        :type data: any
        :rtype: any
        """
        data = force_bytes(data)
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, iv)

    def _encrypt_from_parts(self, data, iv):
        """
        :type data: bytes
        :type iv: bytes
        :rtype: any
        """
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return self._signer.sign(iv + ciphertext)

    def decrypt(self, data, ttl=None):
        """
        :type data: bytes
        :type ttl: int
        :rtype: bytes
        """
        data = self._signer.unsign(data, ttl)

        iv = data[:16]
        ciphertext = data[16:]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded


class Fernet(FernetBytes):
    def __init__(self, key):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )
        from ..core.signing import FernetSigner
        super(Fernet, self).__init__(key[16:], FernetSigner(key[:16]))

    def _encrypt_from_parts(self, data, iv):
        payload = super(Fernet, self)._encrypt_from_parts(data, iv)
        return base64.urlsafe_b64encode(payload)

    def decrypt(self, token, ttl=None):
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, Error):
            raise InvalidToken
        return super(Fernet, self).decrypt(data, ttl)
