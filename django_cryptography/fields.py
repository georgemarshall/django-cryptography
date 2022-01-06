import pickle
from base64 import b64decode, b64encode

from django.core import checks
from django.db import models
from django.utils.encoding import force_bytes
from django.utils.translation import gettext_lazy as _

from django_cryptography.core.signing import SignatureExpired
from django_cryptography.utils.crypto import FernetBytes

FIELD_CACHE = {}

Expired = object()
"""Represents an expired encryption value."""


class PickledField(models.Field):
    """
    A field for storing pickled objects
    """
    description = _("Pickled data")
    empty_values = [None, b'']
    supported_lookups = ('exact', 'in', 'isnull')

    def __init__(self, *args, **kwargs):
        kwargs['editable'] = False
        super(PickledField, self).__init__(*args, **kwargs)

    def _dump(self, value):
        return pickle.dumps(value)

    def _load(self, value):
        return pickle.loads(value)

    def deconstruct(self):
        name, path, args, kwargs = super(PickledField, self).deconstruct()
        del kwargs['editable']
        return name, path, args, kwargs

    def get_internal_type(self):
        return "BinaryField"

    def get_default(self):
        default = super(PickledField, self).get_default()
        if default == '':
            return b''
        return default

    def get_lookup(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(PickledField, self).get_lookup(lookup_name)

    def get_transform(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(PickledField, self).get_transform(lookup_name)

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super(PickledField, self).get_db_prep_value(
            value, connection, prepared)
        if value is not None:
            return connection.Database.Binary(self._dump(value))
        return value

    def from_db_value(self, value, *args, **kwargs):
        if value is not None:
            return self._load(force_bytes(value))
        return value

    def value_to_string(self, obj):
        """Pickled data is serialized as base64"""
        value = self.value_from_object(obj)
        return b64encode(self._dump(value)).decode('ascii')

    def to_python(self, value):
        # If it's a string, it should be base64-encoded data
        if isinstance(value, str):
            return self._load(b64decode(force_bytes(value)))
        return value


class EncryptedMixin:
    """
    A field mixin storing encrypted data

    :param bytes key: This is an optional argument.

        Allows for specifying an instance specific encryption key.
    :param int ttl: This is an optional argument.

        The amount of time in seconds that a value can be stored for. If the
        time to live of the data has passed, it will become unreadable.
        The expired value will return an :class:`Expired` object.
    """
    supported_lookups = ('isnull', )

    def __init__(self, *args, **kwargs):
        self.key = kwargs.pop('key', None)
        self.ttl = kwargs.pop('ttl', None)

        self._fernet = FernetBytes(self.key)
        super(EncryptedMixin, self).__init__(*args, **kwargs)

    @property
    def description(self):
        return _('Encrypted %s') % super(EncryptedMixin, self).description

    def _dump(self, value):
        return self._fernet.encrypt(pickle.dumps(value))

    def _load(self, value):
        try:
            return pickle.loads(self._fernet.decrypt(value, self.ttl))
        except SignatureExpired:
            return Expired

    def check(self, **kwargs):
        errors = super(EncryptedMixin, self).check(**kwargs)
        if getattr(self, 'remote_field', None):
            errors.append(
                checks.Error(
                    'Base field for encrypted cannot be a related field.',
                    hint=None,
                    obj=self,
                    id='encrypted.E002'))
        return errors

    def clone(self):
        name, path, args, kwargs = super(EncryptedMixin, self).deconstruct()
        # Determine if the class that subclassed us has been subclassed.
        if not self.__class__.__mro__.index(EncryptedMixin) > 1:
            return encrypt(
                self.base_class(*args, **kwargs), self.key, self.ttl)
        return self.__class__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(EncryptedMixin, self).deconstruct()
        # Determine if the class that subclassed us has been subclassed.
        if not self.__class__.__mro__.index(EncryptedMixin) > 1:
            path = "%s.%s" % (encrypt.__module__, encrypt.__name__)
            args = [self.base_class(*args, **kwargs)]
            kwargs = {}
            if self.ttl is not None:
                kwargs['ttl'] = self.ttl
        return name, path, args, kwargs

    def get_lookup(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(EncryptedMixin, self).get_lookup(lookup_name)

    def get_transform(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(EncryptedMixin, self).get_transform(lookup_name)

    def get_internal_type(self):
        return "BinaryField"

    def get_db_prep_value(self, value, connection, prepared=False):
        value = models.Field.get_db_prep_value(self, value, connection,
                                               prepared)
        if value is not None:
            return connection.Database.Binary(self._dump(value))
        return value

    get_db_prep_save = models.Field.get_db_prep_save

    def from_db_value(self, value, *args, **kwargs):
        if value is not None:
            return self._load(force_bytes(value))
        return value


def get_encrypted_field(base_class):
    """
    A get or create method for encrypted fields, we cache the field in
    the module to avoid recreation. This also allows us to always return
    the same class reference for a field.

    :type base_class: models.Field[T]
    :rtype: models.Field[EncryptedMixin, T]
    """
    assert not isinstance(base_class, models.Field)
    field_name = 'Encrypted' + base_class.__name__
    if base_class not in FIELD_CACHE:
        FIELD_CACHE[base_class] = type(field_name,
                                       (EncryptedMixin, base_class), {
                                           'base_class': base_class,
                                       })
    return FIELD_CACHE[base_class]


def encrypt(base_field, key=None, ttl=None):
    """
    A decorator for creating encrypted model fields.

    :type base_field: models.Field[T]
    :param bytes key: This is an optional argument.

        Allows for specifying an instance specific encryption key.
    :param int ttl: This is an optional argument.

        The amount of time in seconds that a value can be stored for. If the
        time to live of the data has passed, it will become unreadable.
        The expired value will return an :class:`Expired` object.
    :rtype: models.Field[EncryptedMixin, T]
    """
    if not isinstance(base_field, models.Field):
        assert key is None
        assert ttl is None
        return get_encrypted_field(base_field)

    name, path, args, kwargs = base_field.deconstruct()
    kwargs.update({'key': key, 'ttl': ttl})
    return get_encrypted_field(type(base_field))(*args, **kwargs)
