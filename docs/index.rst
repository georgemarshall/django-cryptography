Welcome to django-crypto
==============================

A set of primitives for easily encrypting data in Django, wrapping
the Python Cryptography_ library. Also provided is a drop in
replacement for Django's own cryptographic primitives, using
Cryptography_ as the backend provider.

Why another encryption library for Django?
------------------------------------------

The motivation for making django-crypto_ was from the
general frustration of existing solutions. Libraries such as
django-cryptographic-fields_ and django-crypto-fields_ do not allow
a way to easily work with custom fields, being limited to their own
provided subset. As well as many others lacking Python 3 and modern
Django support.


.. toctree::
   :maxdepth: 2

   installation
   settings
   fields
   migrating
   examples
   releases


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _Cryptography: https://cryptography.io/
.. _django-crypto: https://github.com/georgemarshall/django-crypto/
.. _django-crypto-fields: https://github.com/erikvw/django-crypto-fields
.. _django-cryptographic-fields: https://github.com/foundertherapy/django-cryptographic-fields/
