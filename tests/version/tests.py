from unittest import TestCase

from django_cryptography import get_version
from django_cryptography.utils.version import get_docs_version


class VersionTests(TestCase):
    def test_development(self):
        ver_tuple = (1, 4, 0, "alpha", 0)
        # This will return a different result when it's run within or outside
        # of a git clone: 1.4.devYYYYMMDDHHMMSS or 1.4.
        ver_string = get_version(ver_tuple)
        self.assertRegexpMatches(ver_string, r"1\.4(\.dev[0-9]+)?")

    def test_releases(self):
        tuples_to_strings = (
            ((1, 4, 0, "alpha", 1), "1.4a1"),
            ((1, 4, 0, "beta", 1), "1.4b1"),
            ((1, 4, 0, "rc", 1), "1.4c1"),
            ((1, 4, 0, "final", 0), "1.4"),
            ((1, 4, 1, "rc", 2), "1.4.1c2"),
            ((1, 4, 1, "final", 0), "1.4.1"),
        )
        for ver_tuple, ver_string in tuples_to_strings:
            self.assertEqual(ver_string, get_version(ver_tuple))

    def test_default(self):
        self.assertTrue(get_version())

    def test_docs_releases(self):
        tuples_to_strings = (
            ((1, 4, 0, "alpha", 1), "dev"),
            ((1, 4, 0, "beta", 1), "dev"),
            ((1, 4, 0, "rc", 1), "dev"),
            ((1, 4, 0, "final", 0), "1.4"),
            ((1, 4, 1, "rc", 2), "dev"),
            ((1, 4, 1, "final", 0), "1.4"),
        )
        for ver_tuple, ver_string in tuples_to_strings:
            self.assertEqual(ver_string, get_docs_version(ver_tuple))
