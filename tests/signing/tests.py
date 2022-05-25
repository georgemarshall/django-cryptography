import datetime
import time

from django.test import SimpleTestCase
from django.test.utils import freeze_time

from django_cryptography.core import signing
from django_cryptography.utils.crypto import InvalidAlgorithm


class TestSigner(SimpleTestCase):
    def test_signature(self):
        """signature() method should generate a signature"""
        signer = signing.Signer("predictable-secret")
        signer2 = signing.Signer("predictable-secret2")
        for s in (
            b"hello",
            b"3098247:529:087:",
            "\u2019".encode(),
        ):
            self.assertEqual(
                signer.signature(s),
                signing.base64_hmac(
                    signer.salt + "signer",
                    s,
                    "predictable-secret",
                    algorithm=signer.algorithm,
                ),
            )
            self.assertNotEqual(signer.signature(s), signer2.signature(s))

    def test_signature_with_salt(self):
        """signature(value, salt=...) should work"""
        signer = signing.Signer("predictable-secret", salt="extra-salt")
        self.assertEqual(
            signer.signature("hello"),
            signing.base64_hmac(
                "extra-salt" + "signer",
                "hello",
                "predictable-secret",
                algorithm=signer.algorithm,
            ),
        )
        self.assertNotEqual(
            signing.Signer("predictable-secret", salt="one").signature("hello"),
            signing.Signer("predictable-secret", salt="two").signature("hello"),
        )

    def test_custom_algorithm(self):
        signer = signing.Signer("predictable-secret", algorithm="sha512")
        self.assertEqual(
            signer.signature("hello"),
            "39g7myx24wdsEj07XSFiTNoGIzdolUgcHk-ynx3nGA8HP-y01_2HLRJIqhNIlkvfb"
            "2wKijVMry1wHKIo66TSTw",
        )

    def test_invalid_algorithm(self):
        signer = signing.Signer("predictable-secret", algorithm="whatever")
        msg = "'whatever' is not an algorithm accepted by the cryptography module."
        with self.assertRaisesMessage(InvalidAlgorithm, msg):
            signer.sign("hello")

    def test_sign_unsign(self):
        """sign/unsign should be reversible"""
        signer = signing.Signer("predictable-secret")
        examples = [
            "q;wjmbk;wkmb",
            "3098247529087",
            "3098247:529:087:",
            "jkw osanteuh ,rcuh nthu aou oauh ,ud du",
            "\u2019",
        ]
        for example in examples:
            signed = signer.sign(example)
            self.assertIsInstance(signed, str)
            self.assertNotEqual(example, signed)
            self.assertEqual(example, signer.unsign(signed))

    def test_sign_unsign_non_string(self):
        signer = signing.Signer("predictable-secret")
        values = [
            123,
            1.23,
            True,
            datetime.date.today(),
        ]
        for value in values:
            with self.subTest(value):
                signed = signer.sign(value)
                self.assertIsInstance(signed, str)
                self.assertNotEqual(signed, value)
                self.assertEqual(signer.unsign(signed), str(value))

    def test_unsign_detects_tampering(self):
        """unsign should raise an exception if the value has been tampered with"""
        signer = signing.Signer("predictable-secret")
        value = "Another string"
        signed_value = signer.sign(value)
        transforms = (
            lambda s: s.upper(),
            lambda s: s + "a",
            lambda s: "a" + s[1:],
            lambda s: s.replace(":", ""),
        )
        self.assertEqual(value, signer.unsign(signed_value))
        for transform in transforms:
            with self.assertRaises(signing.BadSignature):
                signer.unsign(transform(signed_value))

    def test_sign_unsign_object(self):
        signer = signing.Signer("predictable-secret")
        tests = [
            ["a", "list"],
            "a string \u2019",
            {"a": "dictionary"},
        ]
        for obj in tests:
            with self.subTest(obj=obj):
                signed_obj = signer.sign_object(obj)
                self.assertNotEqual(obj, signed_obj)
                self.assertEqual(obj, signer.unsign_object(signed_obj))
                signed_obj = signer.sign_object(obj, compress=True)
                self.assertNotEqual(obj, signed_obj)
                self.assertEqual(obj, signer.unsign_object(signed_obj))

    def test_dumps_loads(self):
        """dumps and loads be reversible for any JSON serializable object"""
        objects = [
            ["a", "list"],
            "a string \u2019",
            {"a": "dictionary"},
        ]
        for o in objects:
            self.assertNotEqual(o, signing.dumps(o))
            self.assertEqual(o, signing.loads(signing.dumps(o)))
            self.assertNotEqual(o, signing.dumps(o, compress=True))
            self.assertEqual(o, signing.loads(signing.dumps(o, compress=True)))

    def test_decode_detects_tampering(self):
        """loads should raise exception for tampered objects"""
        transforms = (
            lambda s: s.upper(),
            lambda s: s + "a",
            lambda s: "a" + s[1:],
            lambda s: s.replace(":", ""),
        )
        value = {
            "foo": "bar",
            "baz": 1,
        }
        encoded = signing.dumps(value)
        self.assertEqual(value, signing.loads(encoded))
        for transform in transforms:
            with self.assertRaises(signing.BadSignature):
                signing.loads(transform(encoded))

    def test_works_with_non_ascii_keys(self):
        binary_key = b"\xe7"  # Set some binary (non-ASCII key)

        s = signing.Signer(binary_key)
        self.assertEqual(
            "foo:fc5zKyRI0Ktcf8db752abovGMa_u2CW9kPCaw5Znhag",
            s.sign("foo"),
        )

    def test_valid_sep(self):
        separators = ["/", "*sep*", ","]
        for sep in separators:
            signer = signing.Signer("predictable-secret", sep=sep)
            self.assertEqual(
                "foo%sLQ8wXoKVFLoLwqvrZsOL9FWEwOy1XDzvduylmAZwNaI" % sep,
                signer.sign("foo"),
            )

    def test_invalid_sep(self):
        """should warn on invalid separator"""
        msg = (
            "Unsafe Signer separator: %r (cannot be empty or consist of only A-z0-9-_=)"
        )
        separators = ["", "-", "abc"]
        for sep in separators:
            with self.assertRaisesMessage(ValueError, msg % sep):
                signing.Signer(sep=sep)


class TestTimestampSigner(SimpleTestCase):
    def test_timestamp_signer(self):
        value = "hello"
        with freeze_time(123456789):
            signer = signing.TimestampSigner("predictable-key")
            ts = signer.sign(value)
            self.assertNotEqual(ts, signing.Signer("predictable-key").sign(value))
            self.assertEqual(signer.unsign(ts), value)

        with freeze_time(123456800):
            self.assertEqual(signer.unsign(ts, max_age=12), value)
            # max_age parameter can also accept a datetime.timedelta object
            self.assertEqual(
                signer.unsign(ts, max_age=datetime.timedelta(seconds=11)), value
            )
            with self.assertRaises(signing.SignatureExpired):
                signer.unsign(ts, max_age=10)


class TestBytesSigner(SimpleTestCase):
    def test_signature(self):
        """signature() method should generate a signature"""
        signer = signing.BytesSigner("predictable-secret")
        signer2 = signing.BytesSigner("predictable-secret2")
        for s in (
            b"hello",
            b"3098247:529:087:",
            "\u2019".encode(),
        ):
            self.assertEqual(
                signer.signature(s),
                signing.salted_hmac(
                    signer.salt + "signer", s, "predictable-secret", algorithm="sha256"
                ).finalize(),
            )
            self.assertNotEqual(signer.signature(s), signer2.signature(s))

    def test_signature_with_salt(self):
        """signature(value, salt=...) should work"""
        signer = signing.BytesSigner("predictable-secret", salt="extra-salt")
        self.assertEqual(
            signer.signature("hello"),
            signing.salted_hmac(
                "extra-salt" + "signer",
                "hello",
                "predictable-secret",
                algorithm="sha256",
            ).finalize(),
        )
        self.assertNotEqual(
            signing.BytesSigner("predictable-secret", salt="one").signature("hello"),
            signing.BytesSigner("predictable-secret", salt="two").signature("hello"),
        )

    def test_sign_unsign(self):
        """sign/unsign should be reversible"""
        signer = signing.BytesSigner("predictable-secret")
        examples = [
            b"q;wjmbk;wkmb",
            b"3098247529087",
            b"3098247:529:087:",
            b"jkw osanteuh ,rcuh nthu aou oauh ,ud du",
            rb"\u2019",
        ]
        for example in examples:
            signed = signer.sign(example)
            self.assertIsInstance(signed, bytes)
            self.assertNotEqual(example, signed)
            self.assertEqual(example, signer.unsign(signed))

    def test_unsign_detects_tampering(self):
        """unsign should raise an exception if the value has been tampered with"""
        signer = signing.BytesSigner("predictable-secret")
        value = b"Another string"
        signed_value = signer.sign(value)
        transforms = (
            lambda s: s.upper(),
            lambda s: s + b"a",
            lambda s: b"a" + s[1:],
        )
        self.assertEqual(value, signer.unsign(signed_value))
        for transform in transforms:
            with self.assertRaises(signing.BadSignature):
                signer.unsign(transform(signed_value))

    def test_dumps_loads(self):
        """dumps and loads be reversible for any JSON serializable object"""
        objects = [
            ["a", "list"],
            "a unicode string \u2019",
            {"a": "dictionary"},
        ]
        for o in objects:
            self.assertNotEqual(o, signing.dumps(o))
            self.assertEqual(o, signing.loads(signing.dumps(o)))
            self.assertNotEqual(o, signing.dumps(o, compress=True))
            self.assertEqual(o, signing.loads(signing.dumps(o, compress=True)))

    def test_decode_detects_tampering(self):
        """loads should raise exception for tampered objects"""
        transforms = (
            lambda s: s.upper(),
            lambda s: s + "a",
            lambda s: "a" + s[1:],
            lambda s: s.replace(":", ""),
        )
        value = {
            "foo": "bar",
            "baz": 1,
        }
        encoded = signing.dumps(value)
        self.assertEqual(value, signing.loads(encoded))
        for transform in transforms:
            with self.assertRaises(signing.BadSignature):
                signing.loads(transform(encoded))

    def test_works_with_non_ascii_keys(self):
        binary_key = b"\xe7"  # Set some binary (non-ASCII key)

        s = signing.BytesSigner(binary_key)
        self.assertEqual(
            b"foo\xb5\x8a\xc47\x19\xaeN\xdcMT\x83{PAb\r"
            b"B\xf3\xd2i\xd1P\x94\xeb^\xc7(\xb4\xd3\x92"
            b"\xd3\xf4",
            s.sign("foo"),
        )


class TestFernetSigner(SimpleTestCase):
    def test_fernet_signer(self):
        value = b"hello"
        with freeze_time(123456789):
            signer = signing.FernetSigner("predictable-key")
            ts = signer.sign(value, int(time.time()))
            self.assertEqual(signer.unsign(ts), value)

        with freeze_time(123456800 + signing._MAX_CLOCK_SKEW):
            self.assertEqual(signer.unsign(ts, max_age=12), value)
            # max_age parameter can also accept a datetime.timedelta object
            self.assertEqual(
                signer.unsign(ts, max_age=datetime.timedelta(seconds=11)), value
            )
            with self.assertRaises(signing.SignatureExpired):
                signer.unsign(ts, max_age=10)

        with freeze_time(123456778 - signing._MAX_CLOCK_SKEW):
            with self.assertRaises(signing.SignatureExpired):
                signer.unsign(ts, max_age=10)

    def test_bad_payload(self):
        signer = signing.FernetSigner("predictable-key")
        value = signer.sign("hello", int(time.time()))

        with self.assertRaises(signing.BadSignature):
            # Break the version
            signer.unsign(b" " + value[1:])

        with self.assertRaises(signing.BadSignature):
            # Break the signature
            signer.unsign(value[:-1] + b" ")

    def test_unsupported(self):
        value = b"hello"
        signer = signing.FernetSigner("predictable-key")

        with self.assertRaises(signing.BadSignature):
            signer.unsign(value)
