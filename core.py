from utils.utils import get_args, check_tools

from modules.shellcode import format_string
from modules.arch import arch_detection
from modules.arch import encode_x86, encode_x64


def main():
    args = get_args()

    try:
        shellcode = format_string(input())
    except ValueError:
        raise ValueError("Shellcode not in valid format")

    if args.bad_chars:
        try:
            bad_chars = format_string(args.bad_chars)
        except ValueError:
            raise ValueError("Badchars not in valid format")

    if not args.arch:
        arch = arch_detection(shellcode)

        if arch is None:
            print("[!] The program failed to determine shellcode architecture\nPlease use -a option to specify it")
            break
    else:
        arch = args.arch

    print(f"[+] Shellcode architecture: {arch}")
    print(f"[+] Shellcode lenght: {len(shellcode)} bytes")

    if arch == "x86":
        encode_x86(shellcode, bad_chars)

    elif arch == "x64":
        encode_x64(shellcode, bad_chars)


if __name__ == "__main__":
    check_tools()
    main()
