from __future__ import unicode_literals

import binascii
import datetime
import re
import struct
import time
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from django.conf import settings
from django.core.signing import (BadSignature, JSONSerializer,
                                 SignatureExpired, b64_decode, b64_encode,
                                 get_cookie_signer)
from django.utils import baseconv
from django.utils.encoding import force_bytes, force_str

from ..utils.crypto import constant_time_compare, salted_hmac

__all__ = [
    'BadSignature', 'SignatureExpired', 'b64_encode', 'b64_decode',
    'base64_hmac', 'get_cookie_signer', 'JSONSerializer', 'dumps', 'loads',
    'Signer', 'TimestampSigner', 'BytesSigner', 'FernetSigner'
]

_MAX_CLOCK_SKEW = 60
_SEP_UNSAFE = re.compile(r'^[A-z0-9-_=]*$')


def base64_hmac(salt, value, key):
    return b64_encode(salted_hmac(salt, value, key).finalize())


def dumps(obj,
          key=None,
          salt='django.core.signing',
          serializer=JSONSerializer,
          compress=False):
    """
    Returns URL-safe, sha1 signed base64 compressed JSON string. If key is
    None, settings.SECRET_KEY is used instead.

    If compress is True (not the default) checks if compressing using zlib can
    save some space. Prepends a '.' to signify compression. This is included
    in the signature, to protect against zip bombs.

    Salt can be used to namespace the hash, so that a signed string is
    only valid for a given namespace. Leaving this at the default
    value or re-using a salt value across different parts of your
    application without good cause is a security risk.

    The serializer is expected to return a bytestring.
    """
    data = serializer().dumps(obj)

    # Flag for if it's been compressed or not
    is_compressed = False

    if compress:
        # Avoid zlib dependency unless compress is being used
        compressed = zlib.compress(data)
        if len(compressed) < (len(data) - 1):
            data = compressed
            is_compressed = True
    base64d = b64_encode(data)
    if is_compressed:
        base64d = b'.' + base64d
    return TimestampSigner(key, salt=salt).sign(base64d)


def loads(s,
          key=None,
          salt='django.core.signing',
          serializer=JSONSerializer,
          max_age=None):
    """
    Reverse of dumps(), raises BadSignature if signature fails.

    The serializer is expected to accept a bytestring.
    """
    # TimestampSigner.unsign always returns unicode but base64 and zlib
    # compression operate on bytes.
    base64d = force_bytes(
        TimestampSigner(key, salt=salt).unsign(s, max_age=max_age))
    decompress = False
    if base64d[:1] == b'.':
        # It's compressed; uncompress it first
        base64d = base64d[1:]
        decompress = True
    data = b64_decode(base64d)
    if decompress:
        data = zlib.decompress(data)
    return serializer().loads(data)


class Signer:
    def __init__(self, key=None, sep=':', salt=None):
        # Use of native strings in all versions of Python
        self.key = key or settings.SECRET_KEY
        self.sep = force_str(sep)
        if _SEP_UNSAFE.match(self.sep):
            raise ValueError(
                'Unsafe Signer separator: %r (cannot be empty or consist of '
                'only A-z0-9-_=)' % sep, )
        self.salt = force_str(
            salt
            or '%s.%s' % (self.__class__.__module__, self.__class__.__name__))

    def signature(self, value):
        signature = base64_hmac(self.salt + 'signer', value, self.key)
        # Convert the signature from bytes to str only on Python 3
        return force_str(signature)

    def sign(self, value):
        value = force_str(value)
        return str('%s%s%s') % (value, self.sep, self.signature(value))

    def unsign(self, signed_value):
        signed_value = force_str(signed_value)
        if self.sep not in signed_value:
            raise BadSignature('No "%s" found in value' % self.sep)
        value, sig = signed_value.rsplit(self.sep, 1)
        if constant_time_compare(sig, self.signature(value)):
            return force_str(value)
        raise BadSignature('Signature "%s" does not match' % sig)


class TimestampSigner(Signer):
    def timestamp(self):
        return baseconv.base62.encode(int(time.time()))

    def sign(self, value):
        value = force_str(value)
        value = str('%s%s%s') % (value, self.sep, self.timestamp())
        return super(TimestampSigner, self).sign(value)

    def unsign(self, value, max_age=None):
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.
        """
        result = super(TimestampSigner, self).unsign(value)
        value, timestamp = result.rsplit(self.sep, 1)
        timestamp = baseconv.base62.decode(timestamp)
        if max_age is not None:
            if isinstance(max_age, datetime.timedelta):
                max_age = max_age.total_seconds()
            # Check timestamp is not older than max_age
            age = time.time() - timestamp
            if age > max_age:
                raise SignatureExpired('Signature age %s > %s seconds' %
                                       (age, max_age))
        return value


class BytesSigner(Signer):
    def __init__(self, key=None, salt=None):
        digest = settings.CRYPTOGRAPHY_DIGEST
        self._digest_size = digest.digest_size
        self.key = key or settings.SECRET_KEY
        self.salt = force_str(
            salt
            or '%s.%s' % (self.__class__.__module__, self.__class__.__name__))

    def signature(self, value):
        return salted_hmac(self.salt + 'signer', value, self.key).finalize()

    def sign(self, value):
        value = force_bytes(value)
        return value + self.signature(value)

    def unsign(self, signed_value):
        value, sig = (signed_value[:-self._digest_size],
                      signed_value[-self._digest_size:])
        if constant_time_compare(sig, self.signature(value)):
            return value
        raise BadSignature(
            'Signature "%s" does not match' % binascii.b2a_base64(sig))


class FernetSigner(Signer):
    version = b'\x80'

    def __init__(self, key=None):
        """
        :type key: any
        :rtype: None
        """
        self.digest = hashes.SHA256()
        self.key = force_bytes(key or settings.SECRET_KEY)

    def signature(self, value):
        """
        :type value: any
        :rtype: HMAC
        """
        h = HMAC(self.key, self.digest, backend=settings.CRYPTOGRAPHY_BACKEND)
        h.update(force_bytes(value))
        return h

    def sign(self, value):
        """
        :type value: any
        :rtype: bytes
        """
        payload = struct.pack('>cQ', self.version, int(time.time()))
        payload += force_bytes(value)
        return payload + self.signature(payload).finalize()

    def unsign(self, signed_value, ttl=None):
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.

        :type signed_value: bytes
        :type ttl: int | datetime.timedelta
        """
        h_size, d_size = struct.calcsize('>cQ'), self.digest.digest_size
        fmt = '>cQ%ds%ds' % (len(signed_value) - h_size - d_size, d_size)
        try:
            version, timestamp, value, sig = struct.unpack(fmt, signed_value)
        except struct.error:
            raise BadSignature('Signature is not valid')
        if version != self.version:
            raise BadSignature('Signature version not supported')
        if ttl is not None:
            if isinstance(ttl, datetime.timedelta):
                ttl = ttl.total_seconds()
            # Check timestamp is not older than ttl
            age = abs(time.time() - timestamp)
            if age > ttl + _MAX_CLOCK_SKEW:
                raise SignatureExpired('Signature age %s > %s seconds' % (age,
                                                                          ttl))
        try:
            self.signature(signed_value[:-d_size]).verify(sig)
        except InvalidSignature:
            raise BadSignature(
                'Signature "%s" does not match' % binascii.b2a_base64(sig))
        return value
