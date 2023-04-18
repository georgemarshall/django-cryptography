from django.db import migrations, models

import django_cryptography.fields


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="EncryptedCharModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("field", models.CharField(max_length=15)),
            ],
        ),
        migrations.CreateModel(
            name="EncryptedDateTimeModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("datetime", models.DateTimeField()),
                ("date", models.DateField()),
                ("time", models.TimeField()),
                ("auto_now", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="EncryptedIntegerModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("field", models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name="EncryptedNullableIntegerModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("field", models.IntegerField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="EncryptedTTLIntegerModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("field", models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name="DefaultPickledModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "field",
                    django_cryptography.fields.PickledField(default=b""),
                ),
            ],
        ),
        migrations.CreateModel(
            name="NullablePickledModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "field",
                    django_cryptography.fields.PickledField(blank=True, null=True),
                ),
            ],
        ),
        migrations.CreateModel(
            name="OtherEncryptedTypesModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("ip", models.GenericIPAddressField()),
                ("uuid", models.UUIDField()),
                ("decimal", models.DecimalField(decimal_places=2, max_digits=5)),
            ],
        ),
        migrations.CreateModel(
            name="PickledModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("field", django_cryptography.fields.PickledField()),
            ],
        ),
    ]
