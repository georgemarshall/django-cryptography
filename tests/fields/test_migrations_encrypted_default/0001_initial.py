from django.db import migrations, models

import django_cryptography.fields


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="IntegerEncryptedDefaultModel",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                ("field", django_cryptography.fields.encrypt(models.IntegerField())),
            ],
        ),
    ]
