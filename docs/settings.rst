Settings
========

:const:`CRYPTOGRAPHY_BACKEND`
-----------------------------

Default: :func:`cryptography.hazmat.backends.default_backend`

:const:`CRYPTOGRAPHY_DIGEST`
----------------------------

Default: :class:`cryptography.hazmat.primitives.hashes.SHA256`

The digest algorithm to use for signing and key generation.

:const:`CRYPTOGRAPHY_KEY`
-------------------------

Default: :obj:`None`

This value should not be used, instead the key will be derived from ``SECRET_KEY``. Due to this depedency please consider whether, and how, the ``SECRET_KEY`` might change after encryption has taken place. 

:const:`CRYPTOGRAPHY_SALT`
--------------------------

Default: ``'django-cryptography'``

Drop-in Replacements
--------------------

:const:`SIGNING_BACKEND`
^^^^^^^^^^^^^^^^^^^^^^^^

The default can be replaced with a a Cryptography_ based version.

.. code-block:: python

   SIGNING_BACKEND = 'django_cryptography.core.signing.TimestampSigner'

.. _Cryptography: https://cryptography.io/
