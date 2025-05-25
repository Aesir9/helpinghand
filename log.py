"""
Just some fancy print function in one place
"""


def info(str, *args, **kwargs):
    print(f'[*] {str}', *args, **kwargs)


def success(str, *args, **kwargs):
    print(f'[+] {str}', *args, **kwargs)


def warning(str, *args, **kwargs):
    print(f'[-] {str}', *args, **kwargs)


def debug(str, *args, **kwargs):
    print(f'[>] {str}', *args, **kwargs)


def critical(str, *args, **kwargs):
    print(f'[!] {str}', *args, **kwargs)


def question(str, *args, **kwargs):
    print(f'[?] {str}', *args, **kwargs)
