# TODO remove this temporary workaround before production
# FIXME add input validation

import subprocess

password = "Admin123456"
api_key = "dummy_api_key_123456789"
TOKEN = "dummy_token_abcdef123456"


def dangerous_eval(user_input):
    # Scanner should detect eval usage
    return eval(user_input)


def risky_shell_call(path):
    # Scanner should detect shell=True
    subprocess.run("dir " + path, shell=True)


def bare_exception_example():
    try:
        result = 10 / 0
        return result
    except:
        pass


def debug_print_example():
    print("debugging local pipeline scanner")
