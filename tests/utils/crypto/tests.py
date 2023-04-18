import hashlib
import time
import unittest

from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.test import SimpleTestCase
from django.test.utils import freeze_time, override_settings
from django.utils.crypto import salted_hmac as django_salted_hmac

from django_cryptography.core import signing
from django_cryptography.utils.crypto import (
    Fernet,
    FernetBytes,
    InvalidAlgorithm,
    InvalidToken,
    constant_time_compare,
    pbkdf2,
    salted_hmac,
)


class TestUtilsCryptoMisc(SimpleTestCase):
    salt = "salted_hmac"
    value = "Hello, World!"

    def test_django_hmac_parity(self):
        django_hmac = django_salted_hmac(self.salt, self.value)
        cryptography_hmac = salted_hmac(self.salt, self.value, algorithm="sha1")

        self.assertEqual(django_hmac.digest(), cryptography_hmac.finalize())

    def test_constant_time_compare(self):
        # It's hard to test for constant time, just test the result.
        self.assertTrue(constant_time_compare(b"spam", b"spam"))
        self.assertFalse(constant_time_compare(b"spam", b"eggs"))
        self.assertTrue(constant_time_compare("spam", "spam"))
        self.assertFalse(constant_time_compare("spam", "eggs"))

    def test_salted_hmac(self):
        tests = [
            ((b"salt", b"value"), {}, "b51a2e619c43b1ca4f91d15c57455521d71d61eb"),
            (("salt", "value"), {}, "b51a2e619c43b1ca4f91d15c57455521d71d61eb"),
            (
                ("salt", "value"),
                {"secret": "abcdefg"},
                "8bbee04ccddfa24772d1423a0ba43bd0c0e24b76",
            ),
            (
                ("salt", "value"),
                {"secret": "x" * hashes.SHA1.block_size},
                "bd3749347b412b1b0a9ea65220e55767ac8e96b0",
            ),
            (
                ("salt", "value"),
                {"algorithm": "sha256"},
                "ee0bf789e4e009371a5372c90f73fcf17695a8439c9108b0480f14e347b3f9ec",
            ),
            (
                ("salt", "value"),
                {
                    "algorithm": "blake2b",
                    "secret": "x" * hashes.BLAKE2b.block_size,
                },
                "fc6b9800a584d40732a07fa33fb69c35211269441823bca431a143853c32f"
                "e836cf19ab881689528ede647dac412170cd5d3407b44c6d0f44630690c54"
                "ad3d58",
            ),
        ]
        for args, kwargs, digest in tests:
            with self.subTest(args=args, kwargs=kwargs):
                self.assertEqual(salted_hmac(*args, **kwargs).finalize().hex(), digest)

    def test_invalid_algorithm(self):
        msg = "'whatever' is not an algorithm accepted by the cryptography module."
        with self.assertRaisesMessage(InvalidAlgorithm, msg):
            salted_hmac("salt", "value", algorithm="whatever")


class TestUtilsCryptoPBKDF2(unittest.TestCase):
    # https://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
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
                "password": b"\xba",
                "salt": "salt",
                "iterations": 1,
                "dklen": 20,
                "digest": hashes.SHA1(),
            },
            "result": "0053d3b91a7f1e54effebd6d68771e8a6e0b2c5b",
        },
        # Check default digest
        {
            "args": {
                "password": "password",
                "salt": "salt",
                "iterations": 1,
                "dklen": 20,
                "digest": None,
            },
            "result": "120fb6cffcf8b32c43e7225256c4f837a86548c9",
        },
    ]

    def test_public_vectors(self):
        for vector in self.rfc_vectors:
            result = pbkdf2(**vector["args"])
            self.assertEqual(result.hex(), vector["result"])

    def test_regression_vectors(self):
        for vector in self.regression_vectors:
            result = pbkdf2(**vector["args"])
            self.assertEqual(result.hex(), vector["result"])

    def test_default_hmac_alg(self):
        kwargs = {
            "password": b"password",
            "salt": b"salt",
            "iterations": 1,
            "dklen": 20,
        }
        self.assertEqual(
            pbkdf2(**kwargs),
            hashlib.pbkdf2_hmac(hash_name=hashlib.sha256().name, **kwargs),
        )


class FernetBytesTestCase(unittest.TestCase):
    def test_cryptography_key(self):
        self.assertEqual(
            settings.CRYPTOGRAPHY_KEY.hex(),
            "83c75905b45ce12bb61d2e883896d274c1790473186692519d076de55c49483c",
        )

    def test_encrypt_decrypt(self):
        value = b"hello"
        iv = b"0123456789abcdef"
        data = (
            "8000000000075bcd15303132333435363738396162636465669a7ce822f47"
            "33dd8ba87469b264d835c34b2892b06ec88098de6bcb6ca662f5e3240d5c2"
            "f5af5728e6198c93a2888b78"
        )
        with freeze_time(123456789):
            fernet = FernetBytes()
            self.assertEqual(
                fernet._encrypt_from_parts(value, int(time.time()), iv),
                bytes.fromhex(data),
            )
            self.assertEqual(fernet.decrypt(bytes.fromhex(data)), value)

    @override_settings(SECRET_KEY="test_key")
    def test_decryptor_invalid_token(self):
        data = (
            "8000000000075bcd153031323334353637383961626364656629b930b1955"
            "ddaec2d74fb4ff565d549d94cc75de940d1d25507f30763f05c412390d15d"
            "a26bccee69f1b4543e75"
        )
        with freeze_time(123456789):
            fernet = FernetBytes()
            with self.assertRaises(InvalidToken):
                fernet.decrypt(bytes.fromhex(data))

    @override_settings(SECRET_KEY="test_key")
    def test_unpadder_invalid_token(self):
        data = (
            "8000000000075bcd15303132333435363738396162636465660ecd40b0f64"
            "8f001b78b5a77b334b40fbbff559444b3325233e71c24e53f6028116b0377"
            "b910ebe5498396de36dee59b"
        )
        with freeze_time(123456789):
            fernet = FernetBytes()
            with self.assertRaises(InvalidToken):
                fernet.decrypt(bytes.fromhex(data))


class StandardFernetTestCase(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        value = b"hello"
        iv = b"0123456789abcdef"
        data = (
            b"gAAAAAAdwJ6wMDEyMzQ1Njc4OWFiY2RlZjYYKxzJY4VTm9YIi4"
            b"Pp6o_RvhRbEt-VW6a0zE-ys6tS1_2Xd2011mjXrVrMV0QfRA=="
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
            Fernet("")

    def test_default_key(self):
        value = b"hello"
        iv = b"0123456789abcdef"
        data = (
            b"gAAAAAAdwJ6wMDEyMzQ1Njc4OWFiY2RlZpp86CL0cz3YuodGmy"
            b"ZNg1zHC5ForoIhr0F33y_CAv2hNHxmx-ZBcM7FK-Fimskaww=="
        )
        with freeze_time(499162800):
            fernet = Fernet()
            self.assertEqual(
                data, fernet._encrypt_from_parts(value, int(time.time()), iv)
            )
            self.assertEqual(value, fernet.decrypt(data, 60))

        with freeze_time(123456789):
            fernet = Fernet()
            with self.assertRaises(signing.SignatureExpired):
                fernet.decrypt(data, 60)

    def test_invalid_type(self):
        key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        fernet = Fernet(key)
        with self.assertRaises(InvalidToken):
            fernet.decrypt("Hi")
