Django Crypto
=============

A set of primitives for easily encrypting data in Django, wrapping
the Python Cryptography_ library. Also provided is a drop in
replacement for Django's own cryptographic primitives, using
Cryptography_ as the backend provider.

Do not forget to read the documentation_.

.. START HIDDEN
.. image:: https://img.shields.io/github/workflow/status/rsp2k/django-crypto/CI/master
   :target: https://github.com/rsp2k/django-crypto/actions/workflows/main.yml
   :alt: GitHub Workflow Status (branch)
.. image:: https://img.shields.io/codecov/c/github/rsp2k/django-crypto/master
   :target: https://app.codecov.io/gh/rsp2k/django-crypto/branch/master
   :alt: Codecov branch
.. END HIDDEN

Cryptography by example
-----------------------

Using symmetrical encryption to store sensitive data in the database.
Wrap the desired model field with ``encrypt`` to easily
protect its contents.

.. code-block:: python

   from django.db import models

   from django_crypto.fields import encrypt


   class MyModel(models.Model):
       name = models.CharField(max_length=50)
       sensitive_data = encrypt(models.CharField(max_length=50))

The data will now be automatically encrypted when saved to the
database.  ``encrypt`` uses an encryption that allows for
bi-directional data retrieval.

Requirements
------------

* Python_ (3.7, 3.8, 3.9, 3.10, 3.11)
* Cryptography_ (2.0+)
* Django_ (3.2, 4.1, 4.2, 5.0+)

Installation
------------

.. code-block:: console

   pip install django-crypto

.. _Cryptography: https://cryptography.io/
.. _Django: https://www.djangoproject.com/
.. _Python: https://www.python.org/
.. _documentation: https://github.com/rsp2k/django-crypto
