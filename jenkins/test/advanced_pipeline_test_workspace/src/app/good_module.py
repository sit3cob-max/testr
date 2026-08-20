import logging
from typing import Iterable

logger = logging.getLogger(__name__)


def calculate_total(values: Iterable[int]) -> int:
    total = 0
    for value in values:
        total += value
    return total


def normalize_name(name: str) -> str:
    return name.strip().title()


if __name__ == "__main__":
    logger.info("Good module loaded")
