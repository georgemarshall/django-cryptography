from django.db import migrations, models

import django_crypto.fields


class Migration(migrations.Migration):
    dependencies = [
        ("fields", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="integerencrypteddefaultmodel",
            name="field_2",
            field=django_crypto.fields.encrypt(
                models.IntegerField(max_length=50, blank=True)
            ),
            preserve_default=False,
        ),
    ]
