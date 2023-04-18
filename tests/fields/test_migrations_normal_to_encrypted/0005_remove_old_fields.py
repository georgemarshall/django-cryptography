from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("fields", "0004_migrate_data"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="encryptedcharmodel",
            name="old_field",
        ),
        migrations.RemoveField(
            model_name="encrypteddatetimemodel",
            name="old_auto_now",
        ),
        migrations.RemoveField(
            model_name="encrypteddatetimemodel",
            name="old_date",
        ),
        migrations.RemoveField(
            model_name="encrypteddatetimemodel",
            name="old_datetime",
        ),
        migrations.RemoveField(
            model_name="encrypteddatetimemodel",
            name="old_time",
        ),
        migrations.RemoveField(
            model_name="encryptedintegermodel",
            name="old_field",
        ),
        migrations.RemoveField(
            model_name="encryptednullableintegermodel",
            name="old_field",
        ),
        migrations.RemoveField(
            model_name="encryptedttlintegermodel",
            name="old_field",
        ),
        migrations.RemoveField(
            model_name="otherencryptedtypesmodel",
            name="old_decimal",
        ),
        migrations.RemoveField(
            model_name="otherencryptedtypesmodel",
            name="old_ip",
        ),
        migrations.RemoveField(
            model_name="otherencryptedtypesmodel",
            name="old_uuid",
        ),
    ]
