Cryptography by example
=======================

Using symmetrical encryption to store sensitive data in the database.
Wrap the desired model field with
:func:`~django_crypto.fields.encrypt` to easily protect its
contents.

.. code-block:: python

   from django.db import models

   from django_crypto.fields import encrypt


   class MyModel(models.Model):
       name = models.CharField(max_length=50)
       sensitive_data = encrypt(models.CharField(max_length=50))

The data will now be automatically encrypted when saved to the
database. :func:`~django_crypto.fields.encrypt` uses an
encryption that allows for bi-directional data retrieval.
