def format_string(string: str):
    return [int(i, 16) for i in string.split("\\x") if i != ""]

def bad_chars_in_shellcode(xored_shellcode: list, bad_chars: list):
    for i in xored_shellcode:
        for j in bad_chars:
            if i == j:
                return True

    return False