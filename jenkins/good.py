# good_code.py

import os
from typing import Optional


def get_application_secret() -> Optional[str]:
    """Fetch secret from environment."""
    return os.getenv("APP_SECRET")


def calculatet: int, second: int) -> int:
    """Simple business logic."""
    return first + second


def validate_username(username: str) -> bool:
    """Validate username."""
    return bool(username and username.strip())


def main() -> None:
    username = "tharun"

    if validate_username(username):
        total = calculate_total(10, 20)
        print(f"Total: {total}")


if __name__ == "__main__":
    main()