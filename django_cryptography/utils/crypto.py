import base64
import os
import time
from binascii import Error
from typing import Dict, Optional, Union

from cryptography.hazmat.primitives import constant_time, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.utils import crypto
from django.utils.encoding import force_bytes

from ..conf import CryptographyConf
from ..typing import Algorithm, Signer

settings = CryptographyConf()


# AddedInDjango30Warning: Remove when Django 2.2 leaves LTS
class InvalidAlgorithm(ValueError):
    """Algorithm is not supported by cryptography."""

    pass


class InvalidToken(Exception):
    pass


HASHES: Dict[Algorithm, hashes.HashAlgorithm] = {
    "blake2b": hashes.BLAKE2b(64),
    "blake2s": hashes.BLAKE2s(32),
    "md5": hashes.MD5(),
    "sha1": hashes.SHA1(),
    "sha224": hashes.SHA224(),
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha3_224": hashes.SHA3_224(),
    "sha3_256": hashes.SHA3_256(),
    "sha3_384": hashes.SHA3_384(),
    "sha3_512": hashes.SHA3_512(),
    "sha512": hashes.SHA512(),
    "sha512_224": hashes.SHA512_224(),
    "sha512_256": hashes.SHA512_256(),
    "sm3": hashes.SM3(),
}


def salted_hmac(
    key_salt: Union[bytes, str],
    value: Union[bytes, str],
    secret: Optional[Union[bytes, str]] = None,
    *,
    algorithm: Algorithm = "sha1",
) -> HMAC:
    """
    Return the HMAC of 'value', using a key generated from key_salt and a
    secret (which defaults to settings.SECRET_KEY). Default algorithm is SHA1,
    but any algorithm name supported by cryptography can be passed.

    A different key_salt should be passed in for every application of HMAC.
    """
    if secret is None:
        secret = settings.SECRET_KEY

    key_salt = force_bytes(key_salt)
    secret = force_bytes(secret)
    try:
        hasher = HASHES[algorithm]
    except KeyError as e:
        raise InvalidAlgorithm(
            "%r is not an algorithm accepted by the cryptography module." % algorithm
        ) from e

    # We need to generate a derived key from our base key.  We can do this by
    # passing the key_salt and our base key through a pseudo-random function.
    digest = hashes.Hash(hasher, backend=settings.CRYPTOGRAPHY_BACKEND)
    digest.update(key_salt + secret)
    key = digest.finalize()

    # If len(key_salt + secret) > sha_constructor().block_size, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.
    h = HMAC(key, hasher, backend=settings.CRYPTOGRAPHY_BACKEND)
    h.update(force_bytes(value))
    return h


get_random_string = crypto.get_random_string


def constant_time_compare(val1: Union[bytes, str], val2: Union[bytes, str]) -> bool:
    """Return True if the two strings are equal, False otherwise."""
    return constant_time.bytes_eq(force_bytes(val1), force_bytes(val2))


def pbkdf2(
    password: Union[bytes, str],
    salt: Union[bytes, str],
    iterations: int,
    dklen: int = 0,
    digest: Optional[hashes.HashAlgorithm] = None,
) -> bytes:
    """
    Implements PBKDF2 with the same API as Django's existing
    implementation, using cryptography.
    """
    if digest is None:
        digest = hashes.SHA256()
    dklen = dklen or digest.digest_size
    password = force_bytes(password)
    salt = force_bytes(salt)
    kdf = PBKDF2HMAC(
        digest, dklen, salt, iterations, backend=settings.CRYPTOGRAPHY_BACKEND
    )
    return kdf.derive(password)


class FernetBytes:
    """
    This is a modified version of the Fernet encryption algorithm from
    the Python Cryptography library. The main change is the allowance
    of varied length cryptographic keys from the base 128-bit. There is
    also an emphasis on using Django's settings system for sane defaults.
    """

    def __init__(
        self, key: Optional[Union[bytes, str]] = None, signer: Optional[Signer] = None
    ) -> None:
        if signer is None:
            from ..core.signing import FernetSigner

            signer = FernetSigner()
        self.key = key or settings.CRYPTOGRAPHY_KEY
        self.signer = signer

    def encrypt(self, data: Union[bytes, str]) -> bytes:
        return self.encrypt_at_time(data, int(time.time()))

    def encrypt_at_time(self, data: Union[bytes, str], current_time: int) -> bytes:
        data = force_bytes(data)
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data: bytes, current_time: int, iv: bytes) -> bytes:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(force_bytes(self.key)),
            modes.CBC(iv),
            backend=settings.CRYPTOGRAPHY_BACKEND,
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return self.signer.sign(iv + ciphertext, current_time)

    def decrypt(self, data: bytes, ttl: Optional[int] = None) -> bytes:
        data = self.signer.unsign(data, ttl)

        iv = data[:16]
        ciphertext = data[16:]
        decryptor = Cipher(
            algorithms.AES(force_bytes(self.key)),
            modes.CBC(iv),
            backend=settings.CRYPTOGRAPHY_BACKEND,
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError as err:
            raise InvalidToken from err

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError as err:
            raise InvalidToken from err
        return unpadded


class Fernet(FernetBytes):
    def __init__(
        self, key: Optional[Union[bytes, str]] = None, signer: Optional[Signer] = None
    ) -> None:
        if signer is None:
            from ..core.signing import FernetSigner

            signer = FernetSigner()
        if key is None:
            super().__init__()
        else:
            key = base64.urlsafe_b64decode(key)
            if len(key) != 32:
                raise ValueError("Fernet key must be 32 url-safe base64-encoded bytes.")

            super().__init__(key[16:], type(signer)(key[:16]))

    def _encrypt_from_parts(self, data: bytes, current_time: int, iv: bytes) -> bytes:
        payload = super()._encrypt_from_parts(data, current_time, iv)
        return base64.urlsafe_b64encode(payload)

    def decrypt(self, token: bytes, ttl: Optional[int] = None) -> bytes:
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, Error) as err:
            raise InvalidToken from err
        return super().decrypt(data, ttl)
