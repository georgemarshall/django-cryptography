DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
    }
}

SECRET_KEY = "django_tests_secret_key"

INSTALLED_APPS = [
    "tests.fields",
]

SIGNING_BACKEND = "django_cryptography.core.signing.TimestampSigner"

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
