import os
import sys

import django
from django.conf import settings
from django.test.utils import get_runner


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

    django.setup()

    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(["tests"])
    dbfile = settings.DATABASES.get("default", {}).get("NAME")
    if dbfile and os.path.exists(dbfile):
        os.remove(dbfile)
    sys.exit(bool(failures))


if __name__ == "__main__":
    main()
