import json
import pickle

from django.core import exceptions, serializers
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from django_cryptography.fields import PickledField

from .models import DefaultPickledModel, NullablePickledModel, PickledModel


class TestSaveLoad(TestCase):
    def test_integer(self):
        instance = PickledModel(field=42)
        instance.save()
        loaded = PickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_string(self):
        instance = PickledModel(field="Hello, world!")
        instance.save()
        loaded = PickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_datetime(self):
        instance = PickledModel(field=timezone.now())
        instance.save()
        loaded = PickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_default(self):
        instance = DefaultPickledModel()
        instance.save()
        loaded = DefaultPickledModel.objects.get(pk=instance.pk)
        self.assertEqual(loaded.field, b"")
        self.assertEqual(instance.field, loaded.field)

    def test_default_null(self):
        instance = NullablePickledModel()
        instance.save()
        loaded = NullablePickledModel.objects.get(pk=instance.pk)
        self.assertEqual(loaded.field, None)
        self.assertEqual(instance.field, loaded.field)

    def test_null_handling(self):
        instance = NullablePickledModel(field=None)
        instance.save()
        loaded = NullablePickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

        instance = PickledModel(field=None)
        with self.assertRaises(IntegrityError):
            instance.save()


class TestQuerying(TestCase):
    def setUp(self):
        self.objs = [
            NullablePickledModel.objects.create(field=[1]),
            NullablePickledModel.objects.create(field=[2]),
            NullablePickledModel.objects.create(field=[2, 3]),
            NullablePickledModel.objects.create(field=[20, 30, 40]),
            NullablePickledModel.objects.create(field=None),
        ]

    def test_exact(self):
        self.assertSequenceEqual(
            NullablePickledModel.objects.filter(field__exact=[1]), self.objs[:1]
        )

    def test_isnull(self):
        self.assertSequenceEqual(
            NullablePickledModel.objects.filter(field__isnull=True), self.objs[-1:]
        )

    def test_in(self):
        self.assertSequenceEqual(
            NullablePickledModel.objects.filter(field__in=[[1], [2]]), self.objs[:2]
        )

    def test_unsupported(self):
        with self.assertRaises(exceptions.FieldError):
            NullablePickledModel.objects.filter(field__contains=[2])


class TestMigrations(TestCase):
    def test_deconstruct(self):
        field = PickledField()
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual("django_cryptography.fields.PickledField", path)
        self.assertEqual(args, [])
        self.assertEqual(kwargs, {})


class TestSerialization(TestCase):
    test_data = (
        (
            # Python 3.4
            '[{"fields": {"field": "gANdcQAoSwFLAk5lLg=="}, '
            '"model": "fields.pickledmodel", "pk": null}]'
        )
        if pickle.HIGHEST_PROTOCOL < 5
        else (
            # Python 3.8
            '[{"fields": {"field": "gASVCgAAAAAAAABdlChLAUsCTmUu"}, '
            '"model": "fields.pickledmodel", "pk": null}]'
        )
    )

    def test_dumping(self):
        instance = PickledModel(field=[1, 2, None])
        data = serializers.serialize("json", [instance])
        self.assertEqual(json.loads(self.test_data), json.loads(data))

    def test_loading(self):
        instance = list(serializers.deserialize("json", self.test_data))[0].object
        self.assertEqual([1, 2, None], instance.field)


class TestValidation(TestCase):
    def test_validate(self):
        field = PickledField()
        field.clean(None, None)
