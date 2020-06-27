import argparse
import subprocess
import shutil

def get_args():

    parser = argparse.ArgumentParser(
        description="Shellcode encoder - A simple shellcode encoder",
        prog="Shellcode encoder",
        epilog="""example:
        ./shellcode_encoder -b "\\x00\\x0a\\x0b" --random <<< "shellcode_here"
        """)

    parser.add_argument('-b', '--bad-chars', type=str, dest="bad_chars", 
        help='''The list of unwanted characters, example:
        Must be in following format: "\\x00\\x0a\\x0b"''')
"""
    parser.add_argument('-r', '--random', action="store_true", dest="random",
        help='''If this option is present, the xor/add/and value will be a random one.
        If this option is not present, the xor/add/and value will the first one found.
    ''')
"""
    parser.add_argument('-a', '--arch', dest="arch", choices=["x86", "x64"],
        help=''' The shellcode architecture, if not specified, architecture dection will be performed
        Supported arch: 
        x86
        x64
        ''')


    args = parser.parse_args()

    return args


def check_tools():
    """
    A simple function to check if required tools are installed,
    if not a message is printed and the program execution is interrupted
    """
    
    if shutil.which("nasm") is None:
        print("`nasm` is required. Please install it.")
        exit(1)

    if shutil.which("objdump") is None:
        print("`objdump` is required. Please install it.")
        exit(1)

    return None