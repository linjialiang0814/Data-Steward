"""Secret buffer helpers."""

from __future__ import annotations


def zero_bytearray(buf: bytearray) -> None:
    for index in range(len(buf)):
        buf[index] = 0
    buf.clear()
