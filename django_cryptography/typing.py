import datetime
from typing import Any, Optional, Union

from typing_extensions import Literal, Protocol

Algorithm = Literal[
    "blake2b",
    "blake2s",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "sha512",
    "sha512_224",
    "sha512_256",
    "sm3",
]


class DBAPI(Protocol):
    def Binary(self, obj: Union[bytes, str]) -> Any:
        ...


class DatabaseWrapper(Protocol):
    Database: DBAPI


class Serializer(Protocol):
    def dumps(self, obj: Any) -> bytes:
        ...

    def loads(self, data: bytes) -> Any:
        ...


class Signer(Protocol):
    def __init__(
        self, key: Optional[Union[bytes, str]] = None, algorithm: Optional[str] = None
    ) -> None:
        ...

    def signature(self, value: Union[bytes, str]) -> bytes:
        ...

    def sign(self, value: Union[bytes, str], current_time: int) -> bytes:
        ...

    def unsign(
        self,
        signed_value: bytes,
        max_age: Optional[Union[int, float, datetime.timedelta]] = None,
    ) -> bytes:
        ...
