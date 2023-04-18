from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("fields", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="encryptedcharmodel",
            old_name="field",
            new_name="old_field",
        ),
        migrations.RenameField(
            model_name="encrypteddatetimemodel",
            old_name="auto_now",
            new_name="old_auto_now",
        ),
        migrations.RenameField(
            model_name="encrypteddatetimemodel",
            old_name="date",
            new_name="old_date",
        ),
        migrations.RenameField(
            model_name="encrypteddatetimemodel",
            old_name="datetime",
            new_name="old_datetime",
        ),
        migrations.RenameField(
            model_name="encrypteddatetimemodel",
            old_name="time",
            new_name="old_time",
        ),
        migrations.RenameField(
            model_name="encryptedintegermodel",
            old_name="field",
            new_name="old_field",
        ),
        migrations.RenameField(
            model_name="encryptednullableintegermodel",
            old_name="field",
            new_name="old_field",
        ),
        migrations.RenameField(
            model_name="encryptedttlintegermodel",
            old_name="field",
            new_name="old_field",
        ),
        migrations.RenameField(
            model_name="otherencryptedtypesmodel",
            old_name="decimal",
            new_name="old_decimal",
        ),
        migrations.RenameField(
            model_name="otherencryptedtypesmodel",
            old_name="ip",
            new_name="old_ip",
        ),
        migrations.RenameField(
            model_name="otherencryptedtypesmodel",
            old_name="uuid",
            new_name="old_uuid",
        ),
    ]
