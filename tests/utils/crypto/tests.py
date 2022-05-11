import binascii
import hashlib
import time
import unittest

from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.test.utils import freeze_time
from django.utils.crypto import pbkdf2 as django_pbkdf2
from django.utils.crypto import salted_hmac as django_salted_hmac

from django_cryptography.core import signing
from django_cryptography.utils.crypto import (
    Fernet,
    FernetBytes,
    InvalidToken,
    constant_time_compare,
    pbkdf2,
    salted_hmac,
)


class TestUtilsCryptoMisc(unittest.TestCase):
    salt = 'salted_hmac'
    value = 'Hello, World!'

    def test_django_hmac_parity(self):
        django_hmac = django_salted_hmac(self.salt, self.value)
        cryptography_hmac = salted_hmac(self.salt, self.value, algorithm='sha1')

        self.assertEqual(django_hmac.digest(), cryptography_hmac.finalize())

    def test_constant_time_compare(self):
        # It's hard to test for constant time, just test the result.
        self.assertTrue(constant_time_compare(b'spam', b'spam'))
        self.assertFalse(constant_time_compare(b'spam', b'eggs'))
        self.assertTrue(constant_time_compare('spam', 'spam'))
        self.assertFalse(constant_time_compare('spam', 'eggs'))


class TestUtilsCryptoPBKDF2(unittest.TestCase):
    digest_map = {
        hashes.MD5: hashlib.md5,
        hashes.SHA1: hashlib.sha1,
        hashes.SHA224: hashlib.sha224,
        hashes.SHA256: hashlib.sha256,
        hashes.SHA384: hashlib.sha384,
        hashes.SHA512: hashlib.sha512,
    }

    # http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
    rfc_vectors = [
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 1,
                "dklen": 20,
                "digest": hashes.SHA1(),
            },
            "result": "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        },
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 2,
                "dklen": 20,
                "digest": hashes.SHA1(),
            },
            "result": "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        },
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 4096,
                "dklen": 20,
                "digest": hashes.SHA1(),
            },
            "result": "4b007901b765489abead49d926f721d065a429c1",
        },
        # # this takes way too long :(
        # {
        #     "args": {
        #         "password": "password",
        #         "salt": "salt",
        #         "iterations": 16777216,
        #         "dklen": 20,
        #         "digest": hashes.SHA1(),
        #     },
        #     "result": "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
        # },
        {
            "args": {
                "password": "passwordPASSWORDpassword",
                "salt": "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                "iterations": 4096,
                "dklen": 25,
                "digest": hashes.SHA1(),
            },
            "result": "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        },
        {
            "args": {
                "password": "pass\0word",
                "salt": "sa\0lt",
                "iterations": 4096,
                "dklen": 16,
                "digest": hashes.SHA1(),
            },
            "result": "56fa6aa75548099dcc37d7f03425e0c3",
        },
    ]

    regression_vectors = [
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 1,
                "dklen": 20,
                "digest": hashes.SHA256(),
            },
            "result": "120fb6cffcf8b32c43e7225256c4f837a86548c9",
        },
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 1,
                "dklen": 20,
                "digest": hashes.SHA512(),
            },
            "result": "867f70cf1ade02cff3752599a3a53dc4af34c7a6",
        },
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 1000,
                "dklen": 0,
                "digest": hashes.SHA512(),
            },
            "result": (
                "afe6c5530785b6cc6b1c6453384731bd5ee432ee"
                "549fd42fb6695779ad8a1c5bf59de69c48f774ef"
                "c4007d5298f9033c0241d5ab69305e7b64eceeb8d"
                "834cfec"
            ),
        },
        # Check leading zeros are not stripped (#17481)
        {
            "args": {
                "password": b'\xba',
                "salt": "salt",
                "iterations": 1,
                "dklen": 20,
                "digest": hashes.SHA1(),
            },
            "result": '0053d3b91a7f1e54effebd6d68771e8a6e0b2c5b',
        },
    ]

    def django_args(self, kwargs):
        kwargs = kwargs.copy()
        kwargs["digest"] = self.digest_map[kwargs["digest"].__class__]
        return kwargs

    def test_defaults(self):
        result = pbkdf2('password', 'salt', 1, digest=hashes.SHA1())
        self.assertEqual(
            '0c60c80f961f0e71f3a9b524af6012062fe037a6',
            binascii.hexlify(result).decode('ascii'),
        )

    def test_public_vectors(self):
        for vector in self.rfc_vectors:
            result = pbkdf2(**vector['args'])
            self.assertEqual(binascii.hexlify(result).decode('ascii'), vector['result'])

    def test_regression_vectors(self):
        for vector in self.regression_vectors:
            result = pbkdf2(**vector['args'])
            self.assertEqual(binascii.hexlify(result).decode('ascii'), vector['result'])

    def test_django_parity(self):
        for vector in self.rfc_vectors:
            self.assertEqual(
                pbkdf2(**vector['args']),
                django_pbkdf2(**self.django_args(vector['args'])),
            )


class FernetBytesTestCase(unittest.TestCase):
    def test_cryptography_key(self):
        self.assertEqual(
            binascii.hexlify(settings.CRYPTOGRAPHY_KEY).decode('ascii'),
            '3af94f1c73e82b00d41d2db759b54af2e31c55dc97a51c3c3ae8b83eb46dd2b8',
        )

    def test_encrypt_decrypt(self):
        value = b'hello'
        iv = b'0123456789abcdef'
        data = (
            '8000000000075bcd153031323334353637383961626364656629b930b1955'
            'ddaec2d74fb4ff565280abdc39baf116e80f116496cde9515bd7d938e5c74'
            'd60bc186286e701ba4fb4004'
        )
        with freeze_time(123456789):
            fernet = FernetBytes()
            self.assertEqual(
                fernet._encrypt_from_parts(value, int(time.time()), iv),
                binascii.unhexlify(data),
            )
            self.assertEqual(fernet.decrypt(binascii.unhexlify(data)), value)

    def test_decryptor_invalid_token(self):
        data = (
            '8000000000075bcd153031323334353637383961626364656629b930b1955'
            'ddaec2d74fb4ff565d549d94cc75de940d1d25507f30763f05c412390d15d'
            'a26bccee69f1b4543e75'
        )
        with freeze_time(123456789):
            fernet = FernetBytes()
            with self.assertRaises(InvalidToken):
                fernet.decrypt(binascii.unhexlify(data))

    def test_unpadder_invalid_token(self):
        data = (
            '8000000000075bcd15303132333435363738396162636465660ecd40b0f64'
            '8f001b78b5a77b334b40fbbff559444b3325233e71c24e53f6028116b0377'
            'b910ebe5498396de36dee59b'
        )
        with freeze_time(123456789):
            fernet = FernetBytes()
            with self.assertRaises(InvalidToken):
                fernet.decrypt(binascii.unhexlify(data))


class StandardFernetTestCase(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = 'cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4='
        value = b'hello'
        iv = b'0123456789abcdef'
        data = (
            b'gAAAAAAdwJ6wMDEyMzQ1Njc4OWFiY2RlZjYYKxzJY4VTm9YIi4'
            b'Pp6o_RvhRbEt-VW6a0zE-ys6tS1_2Xd2011mjXrVrMV0QfRA=='
        )
        with freeze_time(499162800):
            fernet = Fernet(key)
            self.assertEqual(
                data, fernet._encrypt_from_parts(value, int(time.time()), iv)
            )
            self.assertEqual(value, fernet.decrypt(data, 60))

        with freeze_time(123456789):
            fernet = Fernet(key)
            with self.assertRaises(signing.SignatureExpired):
                fernet.decrypt(data, 60)

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            Fernet('')

    def test_invalid_type(self):
        key = 'cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4='
        fernet = Fernet(key)
        with self.assertRaises(InvalidToken):
            fernet.decrypt('Hi')
