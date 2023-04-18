from django.db import migrations, models

import django_cryptography.fields


class Migration(migrations.Migration):
    dependencies = [
        ("fields", "0002_rename_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="encryptedcharmodel",
            name="field",
            field=django_cryptography.fields.encrypt(
                models.CharField(default=None, max_length=15)
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encrypteddatetimemodel",
            name="auto_now",
            field=django_cryptography.fields.encrypt(
                models.DateTimeField(default=None, auto_now=True)
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encrypteddatetimemodel",
            name="date",
            field=django_cryptography.fields.encrypt(models.DateField(default=None)),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encrypteddatetimemodel",
            name="datetime",
            field=django_cryptography.fields.encrypt(
                models.DateTimeField(default=None)
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encrypteddatetimemodel",
            name="time",
            field=django_cryptography.fields.encrypt(models.TimeField(default=None)),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encryptedintegermodel",
            name="field",
            field=django_cryptography.fields.encrypt(models.IntegerField(default=None)),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encryptednullableintegermodel",
            name="field",
            field=django_cryptography.fields.encrypt(
                models.IntegerField(default=None, blank=True, null=True)
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="encryptedttlintegermodel",
            name="field",
            field=django_cryptography.fields.encrypt(
                models.IntegerField(default=None), ttl=60
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="otherencryptedtypesmodel",
            name="decimal",
            field=django_cryptography.fields.encrypt(
                models.DecimalField(default=None, decimal_places=2, max_digits=5)
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="otherencryptedtypesmodel",
            name="ip",
            field=django_cryptography.fields.encrypt(
                models.GenericIPAddressField(default=None)
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="otherencryptedtypesmodel",
            name="uuid",
            field=django_cryptography.fields.encrypt(models.UUIDField(default=None)),
            preserve_default=False,
        ),
    ]
