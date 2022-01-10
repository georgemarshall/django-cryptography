# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import django_cryptography.fields
from django.db import migrations, models


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
