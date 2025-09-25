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

When value is :obj:`None` a key will be derived from
``SECRET_KEY``. Otherwise the value will be used for the key.

:const:`CRYPTOGRAPHY_SALT`
--------------------------

Default: ``'django-crypto'``

Drop-in Replacements
--------------------

:const:`SIGNING_BACKEND`
^^^^^^^^^^^^^^^^^^^^^^^^

The default can be replaced with a a Cryptography_ based version.

.. code-block:: python

   SIGNING_BACKEND = 'django_crypto.core.signing.TimestampSigner'

.. _Cryptography: https://cryptography.io/
