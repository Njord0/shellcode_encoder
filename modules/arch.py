from modules.shellcode import bad_chars_in_shellcode, format_string
from modules.xor import xor_x86, xor_x64

import os
import subprocess
import sys

command = """objdump -d temp_stub.o |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'"""

def arch_detection(shellcode: list):
    """
    This function will try to detect the shellcode architecture
    """

    #x86 detection

    pattern_x86 = 0

    for index in range(0, len(shellcode)):
        if shellcode[index] == 0xcd and shellcode[index+1] == 0x80:
            pattern_x86 += 1

        elif shellcode[index] == 0x31:
            if shellcode[index+1] in (0xc0, 0xf6, 0xff, 0xd2):
                pattern_x86 += 1
            else:
                pattern_x86 += 0.5


    pattern_x64 = 0

    for index in range(0, len(shellcode)):
        if shellcode[index] == 0x0f and shellcode[index+1] == 0x05:
            pattern_x64 += 1

        elif shellcode[index] == 0x48 and shellcode[index+1] == 0x31:
            pattern_x64 += 1

        elif shellcode[index] == 0x48 and hex(shellcode[index+1]) == 0x89:
            pattern_x64 += 1

    if pattern_x86 > pattern_x64:
        return "x86"
    elif pattern_x86 < pattern_x64:
        return "x64"
    else:
        return None


def encode_x86(shellcode: list, bad_chars: list):
    if not xor_x86(shellcode, bad_chars):
        pass

def encode_x64(shellcode: list, bad_chars: list):
    if not xor_x64(shellcode, bad_chars):
        pass
