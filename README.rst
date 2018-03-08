Django Cryptography
===================

A set of primitives for easily encrypting data in Django, wrapping
the Python Cryptography_ library. Also provided is a drop in
replacement for Django's own cryptographic primitives, using
Cryptography_ as the backend provider.

Do not forget to read the documentation_.

.. START HIDDEN
.. image:: https://img.shields.io/travis/georgemarshall/django-cryptography/master.svg
   :target: https://travis-ci.org/georgemarshall/django-cryptography
   :alt: Builds
.. image:: https://img.shields.io/codecov/c/github/georgemarshall/django-cryptography/master.svg
   :target: https://codecov.io/gh/georgemarshall/django-cryptography/branch/master
   :alt: Code coverage
.. image:: https://badge.fury.io/py/django-cryptography.svg
   :target: https://badge.fury.io/py/django-cryptography
   :alt: Code coverage
.. END HIDDEN

Cryptography by example
-----------------------

Using symmetrical encryption to store sensitive data in the database.
Wrap the desired model field with ``encrypt`` to easily
protect its contents.

.. code-block:: python

   from django.db import models

   from django_cryptography.fields import encrypt


   class MyModel(models.Model):
       name = models.CharField(max_length=50)
       sensitive_data = encrypt(models.CharField(max_length=50))

The data will now be automatically encrypted when saved to the
database.  ``encrypt`` uses an encryption that allows for
bi-directional data retrieval.

Requirements
------------

* Python_ (2.7, 3.4, 3.5, 3.6)
* Cryptography_ (2.0+)
* Django_ (1.8, 1.11, 2.0)

Installation
------------

.. code-block:: console

   pip install django-cryptography

.. _Cryptography: https://cryptography.io/
.. _Django: https://www.djangoproject.com/
.. _Python: https://www.python.org/
.. _documentation: https://django-cryptography.readthedocs.io/en/latest/
