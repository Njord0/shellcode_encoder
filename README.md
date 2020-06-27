# shellcode_encoder
Shellcode encoder is a simple python program made in order to create self-decoding shellcode using a xor encoder and a simple stub
It supports both x86 and x86-64 shellcode architecture and you can also precise a list of bytes the encoded shellcode shall not contain (bad chars)

## Requirements
* Python >= 3
* nasm
* objdump

## Installation
```bash
git clone https://github.com/Njord0/shellcode_encoder.git
cd shellcode_encoder
chmod +x core.py
```
And... you are ready to use it !

## Usage

You can display the help message using the -h flag:
```sh
./core.py -h

usage: Shellcode encoder [-h] [-b BAD_CHARS] [-a {x86,x64}]

Shellcode encoder - A simple shellcode encoder

optional arguments:
  -h, --help            show this help message and exit
  -b BAD_CHARS, --bad-chars BAD_CHARS
                        The list of unwanted characters, example: Must be in following format: "\x00\x0a\x0b"
  -a {x86,x64}, --arch {x86,x64}
                        The shellcode architecture, if not specified, architecture dection will be performed Supported arch: x86 x64

example: ./core.py -b "\x00\x11\x0b" --random <<< "shellcode_here"
```
Here is an example command with a x86 shellcode:

```sh
./core.py -b "\x00\x11\xa0" <<< "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

[+] Shellcode architecture: x86
[+] Shellcode lenght: 23 bytes
[+] Working xor value: 1

[+] Stub size: 28 bytes
[+] Final size: 51 bytes

\xeb\x15\x5e\x31\xc0\x31\xdb\x31\xc9\xb3\x17\xb0\x01\x31\x04\x0e\x41\x39\xcb\x75\xf8\xff\xe6\xe8\xe6\xff\xff\xff\x30\xc1\x51\x69\x2e\x2e\x72\x69\x69\x2e\x63\x68\x6f\x88\xe2\x51\x52\x88\xe0\xb1\x0a\xcc\x81
```

As you can see `-a` option is not specified but the program was able to determine the architecture of the shellcode, the program is performing an architecture detection but it might not always work.

