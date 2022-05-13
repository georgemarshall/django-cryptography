import datetime
from typing import Any, Optional, Union

from typing_extensions import Protocol


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
