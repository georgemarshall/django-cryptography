import decimal
import json
import uuid
from io import StringIO

from django import forms
from django.conf import settings
from django.core import exceptions, serializers, validators
from django.core.management import call_command
from django.db import IntegrityError, connection, models
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import freeze_time
from django.utils import timezone

from django_cryptography.fields import Expired, encrypt

from .models import (
    EncryptedCharModel,
    EncryptedDateTimeModel,
    EncryptedFieldSubclass,
    EncryptedIntegerModel,
    EncryptedNullableIntegerModel,
    EncryptedTTLIntegerModel,
    OtherEncryptedTypesModel,
)


class TestSaveLoad(TestCase):
    def test_integer(self):
        instance = EncryptedIntegerModel(field=42)
        instance.save()
        loaded = EncryptedIntegerModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_char(self):
        instance = EncryptedCharModel(field="Hello, world!")
        instance.save()
        loaded = EncryptedCharModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_dates(self):
        instance = EncryptedDateTimeModel(
            datetime=timezone.now(),
            date=timezone.now().date(),
            time=timezone.now().time(),
        )
        instance.save()
        loaded = EncryptedDateTimeModel.objects.get()
        self.assertEqual(instance.datetime, loaded.datetime)
        self.assertEqual(instance.date, loaded.date)
        self.assertEqual(instance.time, loaded.time)
        self.assertTrue(instance.auto_now)
        self.assertEqual(instance.auto_now, loaded.auto_now)

    def test_default_null(self):
        instance = EncryptedNullableIntegerModel()
        instance.save()
        loaded = EncryptedNullableIntegerModel.objects.get(pk=instance.pk)
        self.assertEqual(loaded.field, None)
        self.assertEqual(instance.field, loaded.field)

    def test_null_handling(self):
        instance = EncryptedNullableIntegerModel(field=None)
        instance.save()
        loaded = EncryptedNullableIntegerModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

        instance = EncryptedIntegerModel(field=None)
        with self.assertRaises(IntegrityError):
            instance.save()

    def test_ttl(self):
        with freeze_time(499162800):
            instance = EncryptedTTLIntegerModel(field=42)
            instance.save()

        with freeze_time(123456789):
            loaded = EncryptedTTLIntegerModel.objects.get()
            self.assertIs(loaded.field, Expired)

    def test_other_types(self):
        instance = OtherEncryptedTypesModel(
            ip="192.168.0.1",
            uuid=uuid.uuid4(),
            decimal=decimal.Decimal(1.25),
        )
        instance.save()
        loaded = OtherEncryptedTypesModel.objects.get()
        self.assertEqual(instance.ip, loaded.ip)
        self.assertEqual(instance.uuid, loaded.uuid)
        self.assertEqual(instance.decimal, loaded.decimal)

    def test_updates(self):
        with self.assertNumQueries(2):
            instance = EncryptedCharModel.objects.create(field="Hello, world!")
            instance.field = "Goodbye, world!"
            instance.save()
        loaded = EncryptedCharModel.objects.get()
        self.assertEqual(instance.field, loaded.field)


class TestQuerying(TestCase):
    def setUp(self):
        self.objs = [
            EncryptedNullableIntegerModel.objects.create(field=1),
            EncryptedNullableIntegerModel.objects.create(field=2),
            EncryptedNullableIntegerModel.objects.create(field=3),
            EncryptedNullableIntegerModel.objects.create(field=None),
        ]

    def test_isnull(self):
        self.assertSequenceEqual(
            self.objs[-1:],
            EncryptedNullableIntegerModel.objects.filter(field__isnull=True),
        )

    def test_unsupported(self):
        with self.assertRaises(exceptions.FieldError):
            EncryptedNullableIntegerModel.objects.filter(field__exact=2)


class TestChecks(TestCase):
    def test_settings_has_key(self):
        key = settings.CRYPTOGRAPHY_KEY
        self.assertIsNotNone(key)
        self.assertIsInstance(key, bytes)

    def test_field_description(self):
        field = encrypt(models.IntegerField())
        self.assertEqual("Encrypted Integer", field.description)

    def test_field_checks(self):
        class BadField(models.Model):
            field = encrypt(models.CharField())

            class Meta:
                app_label = "myapp"

        model = BadField()
        errors = model.check()
        self.assertEqual(len(errors), 1)
        # The inner CharField is missing a max_length.
        self.assertEqual("fields.E120", errors[0].id)
        self.assertIn("max_length", errors[0].msg)

    def test_invalid_base_fields(self):
        class Related(models.Model):
            field = encrypt(
                models.ForeignKey("fields.EncryptedIntegerModel", models.CASCADE)
            )

            class Meta:
                app_label = "myapp"

        obj = Related()
        errors = obj.check()
        self.assertEqual(1, len(errors))
        self.assertEqual("encrypted.E002", errors[0].id)


class TestMigrations(TransactionTestCase):
    available_apps = ["tests.fields"]

    def test_clone(self):
        field = encrypt(models.IntegerField())
        new_field = field.clone()
        self.assertIsNot(field, new_field)
        self.assertEqual(field.verbose_name, new_field.verbose_name)
        self.assertNotEqual(field.creation_counter, new_field.creation_counter)

    def test_subclass_clone(self):
        field = EncryptedFieldSubclass()
        new_field = field.clone()
        self.assertIsNot(field, new_field)
        self.assertEqual(field.verbose_name, new_field.verbose_name)
        self.assertNotEqual(field.creation_counter, new_field.creation_counter)

    def test_deconstruct(self):
        field = encrypt(models.IntegerField())
        name, path, args, kwargs = field.deconstruct()
        new = encrypt(*args, **kwargs)
        self.assertEqual(type(new), type(field))

    def test_deconstruct_with_ttl(self):
        field = encrypt(models.IntegerField(), ttl=60)
        name, path, args, kwargs = field.deconstruct()
        new = encrypt(*args, **kwargs)
        self.assertEqual(new.ttl, field.ttl)

    def test_deconstruct_args(self):
        field = encrypt(models.CharField(max_length=20))
        name, path, args, kwargs = field.deconstruct()
        new = encrypt(*args, **kwargs)
        self.assertEqual(new.max_length, field.max_length)

    def test_subclass_deconstruct(self):
        field = encrypt(models.IntegerField())
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual("django_cryptography.fields.encrypt", path)

        field = EncryptedFieldSubclass()
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual("tests.fields.models.EncryptedFieldSubclass", path)

    @override_settings(
        MIGRATION_MODULES={"fields": "tests.fields.test_migrations_encrypted_default"}
    )
    def test_adding_field_with_default(self):
        table_name = "fields_integerencrypteddefaultmodel"
        with connection.cursor() as cursor:
            self.assertNotIn(table_name, connection.introspection.table_names(cursor))
        call_command("migrate", "fields", verbosity=0)
        with connection.cursor() as cursor:
            self.assertIn(table_name, connection.introspection.table_names(cursor))
        call_command("migrate", "fields", "zero", verbosity=0)
        with connection.cursor() as cursor:
            self.assertNotIn(table_name, connection.introspection.table_names(cursor))

    @override_settings(
        MIGRATION_MODULES={"fields": "tests.fields.test_migrations_normal_to_encrypted"}
    )
    def test_makemigrations_no_changes(self):
        out = StringIO()
        call_command("makemigrations", "--dry-run", "fields", stdout=out)
        self.assertIn("No changes detected in app 'fields'", out.getvalue())


class TestSerialization(TestCase):
    test_data_integer = (
        '[{"fields": {"field": 42}, '
        '"model": "fields.encryptedintegermodel", "pk": null}]'
    )
    test_data_char = (
        '[{"fields": {"field": "Hello, world!"}, '
        '"model": "fields.encryptedcharmodel", "pk": null}]'
    )

    def test_integer_dumping(self):
        instance = EncryptedIntegerModel(field=42)
        data = serializers.serialize("json", [instance])
        self.assertEqual(json.loads(self.test_data_integer), json.loads(data))

    def test_integer_loading(self):
        instance = list(serializers.deserialize("json", self.test_data_integer))[
            0
        ].object
        self.assertEqual(42, instance.field)

    def test_char_dumping(self):
        instance = EncryptedCharModel(field="Hello, world!")
        data = serializers.serialize("json", [instance])
        self.assertEqual(json.loads(self.test_data_char), json.loads(data))

    def test_char_loading(self):
        instance = list(serializers.deserialize("json", self.test_data_char))[0].object
        self.assertEqual("Hello, world!", instance.field)


class TestValidation(TestCase):
    def test_unbounded(self):
        field = encrypt(models.IntegerField())
        with self.assertRaises(exceptions.ValidationError) as cm:
            field.clean(None, None)
        self.assertEqual("null", cm.exception.code)
        self.assertEqual("This field cannot be null.", cm.exception.messages[0])

    def test_blank_true(self):
        field = encrypt(models.IntegerField(blank=True, null=True))
        # This should not raise a validation error
        field.clean(None, None)

    def test_with_validators(self):
        field = encrypt(
            models.IntegerField(validators=[validators.MinValueValidator(1)])
        )
        field.clean(1, None)
        with self.assertRaises(exceptions.ValidationError) as cm:
            field.clean(0, None)
        self.assertEqual(
            "Ensure this value is greater than or equal to 1.", cm.exception.messages[0]
        )


class TestFormField(TestCase):
    class EncryptedCharModelForm(forms.ModelForm):
        class Meta:
            fields = "__all__"
            model = EncryptedCharModel

    def test_model_field_formfield(self):
        model_field = encrypt(models.CharField(max_length=27))
        form_field = model_field.formfield()
        self.assertIsInstance(form_field, forms.CharField)
        self.assertEqual(form_field.max_length, 27)

    def test_model_form(self):
        data = {"field": "Hello, world!"}
        form = self.EncryptedCharModelForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual({"field": "Hello, world!"}, form.cleaned_data)

        instance = form.save()
        loaded = EncryptedCharModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_model_form_update(self):
        data = {"field": "Goodbye, world!"}
        instance = EncryptedCharModel.objects.create(field="Hello, world!")
        form = self.EncryptedCharModelForm(data, instance=instance)
        self.assertTrue(form.is_valid(), form.errors)
        form.save()

        loaded = EncryptedCharModel.objects.get()
        self.assertEqual(data["field"], loaded.field)
