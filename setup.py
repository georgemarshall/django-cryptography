#!/usr/bin/env python
import logging
import os
import sys
from codecs import open
from importlib import import_module

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand

if sys.version_info < (3, 0):
    from StringIO import StringIO
else:
    from io import StringIO

BASEDIR = os.path.abspath(os.path.dirname(__file__))
EXCLUDE_FROM_PACKAGES = ["docs", "tests"]

long_description = StringIO()
version = import_module("django_cryptography").get_version()

with open(os.path.join(BASEDIR, "README.rst"), encoding="utf-8") as fp:
    in_block = False
    for line in fp.readlines():
        if not in_block and line.startswith(".. START HIDDEN"):
            in_block = True
        elif in_block and line.startswith(".. END HIDDEN"):
            in_block = False
        elif not in_block:
            long_description.write(line)


# adapted from jaraco.classes.properties:NonDataProperty
class NonDataProperty:
    def __init__(self, fget):
        self.fget = fget

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return self.fget(obj)


class DjangoTest(TestCommand):
    user_options = [
        (
            "settings=",
            None,
            "The Python path to a settings module, e.g. "
            '"myproject.settings.main". If this isn\'t provided, the '
            "DJANGO_SETTINGS_MODULE environment variable will be used.",
        ),
        ("noinput", None, "Tells Django to NOT prompt the user for input of any kind."),
        (
            "failfast",
            None,
            "Tells Django to stop running the test suite after " "first failed test.",
        ),
        (
            "testrunner=",
            None,
            "Tells Django to use specified test runner class "
            "instead of the one specified by the TEST_RUNNER setting.",
        ),
        (
            "liveserver=",
            None,
            "Overrides the default address where the live "
            "server (used with LiveServerTestCase) is expected to run from. The "
            "default value is localhost:8081.",
        ),
        (
            "top-level-directory=",
            "t",
            "Top level of project for unittest " "discovery.",
        ),
        ("pattern=", "p", "The test matching pattern. Defaults to test*.py."),
        ("keepdb", "k", "Preserves the test DB between runs."),
        ("reverse", "r", "Reverses test cases order."),
        ("debug-sql", "d", "Prints logged SQL queries on failure."),
    ]

    def initialize_options(self):
        self.test_suite = "DjangoTest"
        self.settings = None

        self.test_labels = None
        self.noinput = 0
        self.failfast = 0
        self.testrunner = None
        self.liveserver = None

        self.top_level_directory = None
        self.pattern = None
        self.keepdb = False
        self.reverse = False
        self.debug_sql = False

        self.output_dir = None

    def finalize_options(self):
        self.verbosity = self.verbose
        if self.settings:
            os.environ["DJANGO_SETTINGS_MODULE"] = self.settings

        if self.test_labels is not None:
            self.test_labels = self.test_labels.split(",")
        self.noinput = bool(self.noinput)
        self.failfast = bool(self.failfast)
        if self.liveserver is not None:
            os.environ["DJANGO_LIVE_TEST_SERVER_ADDRESS"] = self.liveserver

        if self.pattern is None:
            self.pattern = "test*.py"
        self.keepdb = bool(self.keepdb)
        self.reverse = bool(self.reverse)
        self.debug_sql = bool(self.debug_sql)

        if self.output_dir is None:
            self.output_dir = "testxml"

    @NonDataProperty
    def test_args(self):
        return list(self._test_args())

    def _test_args(self):
        if self.verbose:
            yield "--verbose"
        if self.test_suite:
            yield self.test_suite

    def run(self):
        if self.verbosity > 0:
            # ensure that deprecation warnings are displayed during testing
            # the following state is assumed:
            # logging.capturewarnings is true
            # a "default" level warnings filter has been added for
            # DeprecationWarning. See django.conf.LazySettings._configure_logging
            logger = logging.getLogger("py.warnings")
            handler = logging.StreamHandler()
            logger.addHandler(handler)
        TestCommand.run(self)
        if self.verbosity > 0:
            # remove the testing-specific handler
            logger.removeHandler(handler)

    def run_tests(self):
        import django

        django.setup()

        from django.conf import settings
        from django.test.utils import get_runner

        TestRunner = get_runner(settings, self.testrunner)

        test_runner = TestRunner(
            pattern=self.pattern,
            top_level=self.top_level_directory,
            verbosity=self.verbose,
            interactive=(not self.noinput),
            failfast=self.failfast,
            keepdb=self.keepdb,
            reverse=self.reverse,
            debug_sql=self.debug_sql,
            output_dir=self.output_dir,
        )
        failures = test_runner.run_tests(self.test_labels)

        sys.exit(bool(failures))


setup(
    name="django-cryptography",
    version=version,
    description="Easily encrypt data in Django",
    long_description=long_description.getvalue(),
    url="https://github.com/georgemarshall/django-cryptography",
    author="George Marshall",
    author_email="george@georgemarshall.name",
    license="BSD",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.11",
        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3.0",
        "Framework :: Django :: 4.0",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security :: Cryptography",
    ],
    packages=find_packages(exclude=EXCLUDE_FROM_PACKAGES),
    install_requires=[
        "django-appconf",
        "cryptography",
    ],
    tests_require=["Django"],
    cmdclass={
        "test": DjangoTest,
    },
    zip_safe=False,
)
