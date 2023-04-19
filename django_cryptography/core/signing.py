import binascii
import datetime
import struct
import time
import zlib
from typing import Any, Optional, Type, Union

from cryptography.hazmat.primitives.hmac import HMAC
from django.conf import settings
from django.core.signing import (
    BadSignature,
    JSONSerializer,
    SignatureExpired,
    b64_decode,
    b64_encode,
    get_cookie_signer,
)
from django.utils.encoding import force_bytes
from django.utils.regex_helper import _lazy_re_compile

from ..typing import Algorithm, Serializer
from ..utils.crypto import HASHES, InvalidAlgorithm, constant_time_compare, salted_hmac

try:
    from django.core.signing import b62_decode, b62_encode  # type: ignore
except ImportError:
    from django.utils import baseconv

    # Required for Django 3.2 support
    b62_decode, b62_encode = baseconv.base62.decode, baseconv.base62.encode

__all__ = [
    "BadSignature",
    "SignatureExpired",
    "b64_encode",
    "b64_decode",
    "base64_hmac",
    "get_cookie_signer",
    "JSONSerializer",
    "dumps",
    "loads",
    "Signer",
    "TimestampSigner",
    "BytesSigner",
    "FernetSigner",
]

_MAX_CLOCK_SKEW = 60
_SEP_UNSAFE = _lazy_re_compile(r"^[A-z0-9-_=]*$")


def base64_hmac(
    salt: str,
    value: Union[bytes, str],
    key: Union[bytes, str],
    algorithm: Algorithm = "sha1",
) -> str:
    return b64_encode(
        salted_hmac(salt, value, key, algorithm=algorithm).finalize()
    ).decode()


def dumps(
    obj: Any,
    key: Optional[Union[bytes, str]] = None,
    salt: str = "django.core.signing",
    serializer: Type[Serializer] = JSONSerializer,
    compress: bool = False,
) -> str:
    """
    Return URL-safe, hmac signed base64 compressed JSON string. If key is
    None, use settings.SECRET_KEY instead. The hmac algorithm is the default
    Signer algorithm.

    If compress is True (not the default), check if compressing using zlib can
    save some space. Prepend a '.' to signify compression. This is included
    in the signature, to protect against zip bombs.

    Salt can be used to namespace the hash, so that a signed string is
    only valid for a given namespace. Leaving this at the default
    value or re-using a salt value across different parts of your
    application without good cause is a security risk.

    The serializer is expected to return a bytestring.
    """
    return TimestampSigner(key, salt=salt).sign_object(
        obj, serializer=serializer, compress=compress
    )


def loads(
    s: str,
    key: Optional[Union[bytes, str]] = None,
    salt: str = "django.core.signing",
    serializer: Type[Serializer] = JSONSerializer,
    max_age: Optional[Union[int, datetime.timedelta]] = None,
) -> Any:
    """
    Reverse of dumps(), raise BadSignature if signature fails.

    The serializer is expected to accept a bytestring.
    """
    return TimestampSigner(key, salt=salt).unsign_object(
        s, serializer=serializer, max_age=max_age
    )


class Signer:
    def __init__(
        self,
        key: Optional[Union[bytes, str]] = None,
        sep: str = ":",
        salt: Optional[str] = None,
        algorithm: Optional[Algorithm] = None,
    ) -> None:
        # Use of native strings in all versions of Python
        self.key = key or settings.SECRET_KEY
        self.sep = sep
        if _SEP_UNSAFE.match(self.sep):
            raise ValueError(
                "Unsafe Signer separator: %r (cannot be empty or consist of "
                "only A-z0-9-_=)" % sep,
            )
        self.salt = salt or f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.algorithm = algorithm or "sha256"

    def signature(self, value: Union[bytes, str]) -> str:
        return base64_hmac(
            self.salt + "signer", value, self.key, algorithm=self.algorithm
        )

    def sign(self, value: str) -> str:
        return f"{value}{self.sep}{self.signature(value)}"

    def unsign(self, signed_value: str) -> str:
        if self.sep not in signed_value:
            raise BadSignature('No "%s" found in value' % self.sep)
        value, sig = signed_value.rsplit(self.sep, 1)
        if constant_time_compare(sig, self.signature(value)):
            return value
        raise BadSignature('Signature "%s" does not match' % sig)

    def sign_object(
        self,
        obj: Any,
        serializer: Type[Serializer] = JSONSerializer,
        compress: bool = False,
    ) -> str:
        """
        Return URL-safe, hmac signed base64 compressed JSON string.

        If compress is True (not the default), check if compressing using zlib
        can save some space. Prepend a '.' to signify compression. This is
        included in the signature, to protect against zip bombs.

        The serializer is expected to return a bytestring.
        """
        data = serializer().dumps(obj)
        # Flag for if it's been compressed or not.
        is_compressed = False

        if compress:
            # Avoid zlib dependency unless compress is being used.
            compressed = zlib.compress(data)
            if len(compressed) < (len(data) - 1):
                data = compressed
                is_compressed = True
        base64d = b64_encode(data).decode()
        if is_compressed:
            base64d = "." + base64d
        return self.sign(base64d)

    def unsign_object(
        self,
        signed_obj: str,
        serializer: Type[Serializer] = JSONSerializer,
        **kwargs: Any,
    ) -> Any:
        # Signer.unsign() returns str but base64 and zlib compression operate
        # on bytes.
        base64d = self.unsign(signed_obj, **kwargs).encode()
        decompress = base64d[:1] == b"."
        if decompress:
            # It's compressed; uncompress it first.
            base64d = base64d[1:]
        data = b64_decode(base64d)
        if decompress:
            data = zlib.decompress(data)
        return serializer().loads(data)


class TimestampSigner(Signer):
    def timestamp(self) -> str:
        return b62_encode(int(time.time()))

    def sign(self, value: str) -> str:
        value = f"{value}{self.sep}{self.timestamp()}"
        return super().sign(value)

    def unsign(
        self,
        value: str,
        max_age: Optional[Union[int, float, datetime.timedelta]] = None,
    ) -> str:
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.
        """
        result = super().unsign(value)
        value, timestamp = result.rsplit(self.sep, 1)
        if max_age is not None:
            if isinstance(max_age, datetime.timedelta):
                max_age = max_age.total_seconds()
            # Check timestamp is not older than max_age
            age = time.time() - b62_decode(timestamp)
            if age > max_age:
                raise SignatureExpired(f"Signature age {age} > {max_age} seconds")
        return value


class BytesSigner:
    def __init__(
        self,
        key: Optional[Union[bytes, str]] = None,
        salt: Optional[str] = None,
        algorithm: Optional[Algorithm] = None,
    ) -> None:
        self.key = key or settings.SECRET_KEY
        self.salt = salt or f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.algorithm = algorithm or "sha256"

        try:
            hasher = HASHES[self.algorithm]
        except KeyError as e:
            raise InvalidAlgorithm(
                "%r is not an algorithm accepted by the cryptography module."
                % algorithm
            ) from e

        self._digest_size = hasher.digest_size

    def signature(self, value: Union[bytes, str]) -> bytes:
        return salted_hmac(
            self.salt + "signer", value, self.key, algorithm=self.algorithm
        ).finalize()

    def sign(self, value: Union[bytes, str]) -> bytes:
        return force_bytes(value) + self.signature(value)

    def unsign(self, signed_value: bytes) -> bytes:
        value, sig = (
            signed_value[: -self._digest_size],
            signed_value[-self._digest_size :],
        )
        if constant_time_compare(sig, self.signature(value)):
            return value
        raise BadSignature('Signature "%r" does not match' % binascii.b2a_base64(sig))


class FernetSigner:
    version = b"\x80"

    def __init__(
        self,
        key: Optional[Union[bytes, str]] = None,
        algorithm: Optional[Algorithm] = None,
    ) -> None:
        self.key = key or settings.SECRET_KEY
        self.algorithm = algorithm or "sha256"

        try:
            hasher = HASHES[self.algorithm]
        except KeyError as e:
            raise InvalidAlgorithm(
                "%r is not an algorithm accepted by the cryptography module."
                % algorithm
            ) from e

        self.hasher = hasher

    def signature(self, value: Union[bytes, str]) -> bytes:
        h = HMAC(
            force_bytes(self.key),
            self.hasher,
            backend=settings.CRYPTOGRAPHY_BACKEND,  # type: ignore
        )
        h.update(force_bytes(value))
        return h.finalize()

    def sign(self, value: Union[bytes, str], current_time: int) -> bytes:
        payload = struct.pack(">cQ", self.version, current_time)
        payload += force_bytes(value)
        return payload + self.signature(payload)

    def unsign(
        self,
        signed_value: bytes,
        max_age: Optional[Union[int, float, datetime.timedelta]] = None,
    ) -> bytes:
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.
        """
        h_size, d_size = struct.calcsize(">cQ"), self.hasher.digest_size
        fmt = ">cQ%ds%ds" % (len(signed_value) - h_size - d_size, d_size)
        try:
            version, timestamp, value, sig = struct.unpack(fmt, signed_value)
        except struct.error as err:
            raise BadSignature("Signature is not valid") from err
        if version != self.version:
            raise BadSignature("Signature version not supported")
        if max_age is not None:
            if isinstance(max_age, datetime.timedelta):
                max_age = max_age.total_seconds()
            # Check timestamp is not older than max_age
            age = abs(time.time() - timestamp)
            if age > max_age + _MAX_CLOCK_SKEW:
                raise SignatureExpired(f"Signature age {age} > {max_age} seconds")
        if constant_time_compare(sig, self.signature(signed_value[:-d_size])):
            return value
        raise BadSignature('Signature "%r" does not match' % binascii.b2a_base64(sig))
