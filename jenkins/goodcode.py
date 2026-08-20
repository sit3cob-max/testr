import os

password = os.getenv("APP_PASSWORD")

def validate_user(name):
    return bool(name)

validate_user("Tharunn")