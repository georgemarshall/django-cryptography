Migrating existing data
=======================

.. seealso::

   If you are unfamiliar with migrations in Django, please consult
   the `Django Migrations`_ documentation.

To migrate an unencrypted database field to an encrypted field the
following steps must be followed. Each step is labeled with its
Django migration type of schema or data.

1. Rename existing field using a prefix such as ``old_`` (schema)
2. Add new encrypted field with name of the original field (schema)
3. Copy data from the old field into the new field (data)
4. Remove the old field (schema)

The steps are illustrated bellow for the following model:

.. code-block:: python

   class EncryptedCharModel(models.Model):
       field = encrypt(models.CharField(max_length=15))

Create the initial migration for the `EncryptedCharModel`.

.. code-block:: python

   class Migration(migrations.Migration):

       initial = True

       dependencies = []

       operations = [
           migrations.CreateModel(
               name='EncryptedCharModel',
               fields=[
                   ('id', models.AutoField(
                       auto_created=True,
                       primary_key=True,
                       serialize=False,
                       verbose_name='ID')),
                   ('field', models.CharField(max_length=15)),
               ],
           ),
       ]

Rename the old field by pre-fixing as ``old_field`` from ``field``

.. code-block:: python

   class Migration(migrations.Migration):

       dependencies = [
           ('fields', '0001_initial'),
       ]

       operations = [
           migrations.RenameField(
               model_name='encryptedcharmodel',
               old_name='field',
               new_name='old_field',
           ),
       ]

Add the new encrypted field using the original name from our field.

.. code-block:: python

   class Migration(migrations.Migration):

       dependencies = [
           ('fields', '0002_rename_fields'),
       ]

       operations = [
           migrations.AddField(
               model_name='encryptedcharmodel',
               name='field',
               field=django_crypto.fields.encrypt(
                   models.CharField(default=None, max_length=15)),
               preserve_default=False,
           ),
       ]

Copy the data from the old field into the new field using the ORM.
Providing forwards and reverse methods will allow restoring the field
to its unencrypted form.

.. code-block:: python

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


   class Migration(migrations.Migration):

       dependencies = [
           ("fields", "0003_add_encrypted_fields"),
       ]

       operations = [
           migrations.RunPython(forwards_encrypted_char, reverse_encrypted_char),
       ]

Delete the old field now that the data has been copied into the new field

.. code-block:: python

   class Migration(migrations.Migration):

       dependencies = [
           ('fields', '0004_migrate_data'),
       ]

       operations = [
           migrations.RemoveField(
               model_name='encryptedcharmodel',
               name='old_field',
           ),
       ]

.. _`Django Migrations`: https://docs.djangoproject.com/en/stable/topics/migrations/
