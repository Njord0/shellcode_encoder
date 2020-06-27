from modules.shellcode import bad_chars_in_shellcode, format_string
from modules.commands import command

import subprocess
import os

def xor_x86(shellcode: list, bad_chars: list):
    for k in range(1, 256):
        xored_shellcode = [j ^ k for j in shellcode]

        if bad_chars_in_shellcode(xored_shellcode, bad_chars):
            continue

        print(f"[+] Working xor value: {k}", end="\n\n")

        with open("modules/architectures/x86/xor_stub.s", "r") as stub:
            lines = stub.readlines()

            shellc = ",".join(hex(c) for c in xored_shellcode)

            for i in range(0, len(lines)):
                lines[i] = lines[i].replace("{encoded_shellcode_size}", str(len(xored_shellcode)))
                lines[i] = lines[i].replace("{xor_key}", str(k))
                lines[i] = lines[i].replace("{shellcode}", shellc)

            with open("temp_stub.s", "w") as temp:
                temp.writelines(lines)

            break

    else:
        return False

    try:
        out = subprocess.check_output(["nasm", "-f", "elf32", "temp_stub.s"])
    except subprocess.CalledProcessError:
        print("[!] Error.")
        exit(-1)
        
    if "fatal" in out.decode():
        print("[!] Error while building shellcode...")
        exit(-1)

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    out = process.communicate()[0].decode().replace("\"", "")
    shellcode_final = out.replace("x", "\\x")

    os.remove("temp_stub.s")
    os.remove("temp_stub.o")

    if bad_chars_in_shellcode(format_string(shellcode_final), bad_chars):
        print("[!] Bad chars in final encoded shellcode")
        return False

    print("[+] Stub size: {} bytes".format(len(format_string(shellcode_final)) - len(shellcode)))
    print("[+] Final size: {} bytes\n".format(len(format_string(shellcode_final))))

    print(shellcode_final)

    return True


def xor_x64(shellcode: list, bad_chars: list):
    for k in range(1, 256):
        xored_shellcode = [i ^ k for i in shellcode]

        if bad_chars_in_shellcode(shellcode, bad_chars):
            continue

        print(f"[+] Working xor value: {k}", end="\n\n")

        with open("modules/architectures/x64/xor_stub.s", "r") as stub:
            lines = stub.readlines()

            shellc = ",".join(hex(c) for c in xored_shellcode)

            for i in range(0, len(lines)):
                lines[i] = lines[i].replace("{encoded_shellcode_size}", str(len(xored_shellcode)))
                lines[i] = lines[i].replace("{xor_key}", str(k))
                lines[i] = lines[i].replace("{shellcode}", shellc)

            with open("temp_stub.s", "w") as temp:
                temp.writelines(lines)

            break
    else:
        return False
    try:
        out = subprocess.check_output(["nasm", "-f", "elf64", "temp_stub.s"])
    except subprocess.CalledProcessError:
        print("[!] Error.")
        exit(-1)


    if "fatal" in out.decode():
        print("[!] Error while building shellcode...")
        exit(-1)

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    out = process.communicate()[0].decode().replace("\"", "")
    shellcode_final = out.replace("x", "\\x")

    os.remove("temp_stub.s")
    os.remove("temp_stub.o")

    if bad_chars_in_shellcode(format_string(shellcode_final), bad_chars):
        print("[!] Bad chars in final encoded shellcode")
        return False

    print("[+] Stub size: {} bytes".format(len(format_string(shellcode_final)) - len(shellcode)))
    print("[+] Final size: {} bytes\n".format(len(format_string(shellcode_final))))

    print(shellcode_final)

    return True
