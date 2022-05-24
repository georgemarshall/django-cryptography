from django.db import models

from django_cryptography.fields import PickledField, encrypt


class PickledModel(models.Model):
    field = PickledField()


class DefaultPickledModel(models.Model):
    field = PickledField(default=b"")


class NullablePickledModel(models.Model):
    field = PickledField(blank=True, null=True)


class EncryptedIntegerModel(models.Model):
    field = encrypt(models.IntegerField())


class EncryptedNullableIntegerModel(models.Model):
    field = encrypt(models.IntegerField(blank=True, null=True))


class EncryptedTTLIntegerModel(models.Model):
    field = encrypt(models.IntegerField(), ttl=60)


class EncryptedCharModel(models.Model):
    field = encrypt(models.CharField(max_length=15))


class EncryptedDateTimeModel(models.Model):
    datetime = encrypt(models.DateTimeField())
    date = encrypt(models.DateField())
    time = encrypt(models.TimeField())
    auto_now = encrypt(models.DateTimeField(auto_now=True))


class OtherEncryptedTypesModel(models.Model):
    ip = encrypt(models.GenericIPAddressField())
    uuid = encrypt(models.UUIDField())
    decimal = encrypt(models.DecimalField(max_digits=5, decimal_places=2))


@encrypt
class EncryptedFieldSubclass(models.IntegerField):
    pass
