from django.db import migrations


def forwards_encrypted_char(apps, schema_editor):
    EncryptedCharModel = apps.get_model("fields", "EncryptedCharModel")

    for row in EncryptedCharModel.objects.all():
        row.field = row.old_field
        row.save(update_fields=["field"])


def reverse_encrypted_char(apps, schema_editor):
    EncryptedCharModel = apps.get_model("fields", "EncryptedCharModel")

    for row in EncryptedCharModel.objects.all():
        row.old_field = row.field
        row.save(update_fields=["old_field"])


def forwards_encrypted_date_time(apps, schema_editor):
    EncryptedDateTimeModel = apps.get_model("fields", "EncryptedDateTimeModel")

    for row in EncryptedDateTimeModel.objects.all():
        row.auto_now = row.old_auto_now
        row.date = row.old_date
        row.datetime = row.old_datetime
        row.time = row.old_time
        row.save(update_fields=["auto_now", "date", "datetime", "time"])


def reverse_encrypted_date_time(apps, schema_editor):
    EncryptedDateTimeModel = apps.get_model("fields", "EncryptedDateTimeModel")

    for row in EncryptedDateTimeModel.objects.all():
        row.old_auto_now = row.auto_now
        row.old_date = row.date
        row.old_datetime = row.datetime
        row.old_time = row.time
        row.save(update_fields=["old_auto_now", "old_date", "old_datetime", "old_time"])


def forwards_encrypted_integer(apps, schema_editor):
    EncryptedIntegerModel = apps.get_model("fields", "EncryptedIntegerModel")

    for row in EncryptedIntegerModel.objects.all():
        row.field = row.old_field
        row.save(update_fields=["field"])


def reverse_encrypted_integer(apps, schema_editor):
    EncryptedIntegerModel = apps.get_model("fields", "EncryptedIntegerModel")

    for row in EncryptedIntegerModel.objects.all():
        row.old_field = row.field
        row.save(update_fields=["old_field"])


def forwards_encrypted_nullable_integer(apps, schema_editor):
    EncryptedNullableIntegerModel = apps.get_model(
        "fields", "EncryptedNullableIntegerModel"
    )

    for row in EncryptedNullableIntegerModel.objects.all():
        row.field = row.old_field
        row.save(update_fields=["field"])


def reverse_encrypted_nullable_integer(apps, schema_editor):
    EncryptedNullableIntegerModel = apps.get_model(
        "fields", "EncryptedNullableIntegerModel"
    )

    for row in EncryptedNullableIntegerModel.objects.all():
        row.old_field = row.field
        row.save(update_fields=["old_field"])


def forwards_encrypted_ttl_integer(apps, schema_editor):
    EncryptedTTLIntegerModel = apps.get_model("fields", "EncryptedTTLIntegerModel")

    for row in EncryptedTTLIntegerModel.objects.all():
        row.field = row.old_field
        row.save(update_fields=["field"])


def reverse_encrypted_ttl_integer(apps, schema_editor):
    EncryptedTTLIntegerModel = apps.get_model("fields", "EncryptedTTLIntegerModel")

    for row in EncryptedTTLIntegerModel.objects.all():
        row.old_field = row.field
        row.save(update_fields=["old_field"])


def forwards_other_encrypted_types(apps, schema_editor):
    OtherEncryptedTypesModel = apps.get_model("fields", "OtherEncryptedTypesModel")

    for row in OtherEncryptedTypesModel.objects.all():
        row.decimal = row.old_decimal
        row.ip = row.old_ip
        row.uuid = row.old_uuid
        row.save(update_fields=["decimal", "ip", "uuid"])


def reverse_other_encrypted_types(apps, schema_editor):
    OtherEncryptedTypesModel = apps.get_model("fields", "OtherEncryptedTypesModel")

    for row in OtherEncryptedTypesModel.objects.all():
        row.old_decimal = row.decimal
        row.old_ip = row.ip
        row.old_uuid = row.uuid
        row.save(update_fields=["old_decimal", "old_ip", "old_uuid"])


class Migration(migrations.Migration):
    dependencies = [
        ("fields", "0003_add_encrypted_fields"),
    ]

    operations = [
        migrations.RunPython(forwards_encrypted_char, reverse_encrypted_char),
        migrations.RunPython(forwards_encrypted_date_time, reverse_encrypted_date_time),
        migrations.RunPython(forwards_encrypted_integer, reverse_encrypted_integer),
        migrations.RunPython(
            forwards_encrypted_nullable_integer, reverse_encrypted_nullable_integer
        ),
        migrations.RunPython(
            forwards_encrypted_ttl_integer, reverse_encrypted_ttl_integer
        ),
        migrations.RunPython(
            forwards_other_encrypted_types, reverse_other_encrypted_types
        ),
    ]
