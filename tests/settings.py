SECRET_KEY = "test_key"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
    }
}

INSTALLED_APPS = [
    "tests.fields",
]

SIGNING_BACKEND = "django_cryptography.core.signing.TimestampSigner"
