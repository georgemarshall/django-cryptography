SECRET_KEY = 'test_key'
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
    }
}

INSTALLED_APPS = [
    'tests.fields',
]

SIGNING_BACKEND = 'django_cryptography.core.signing.TimestampSigner'
