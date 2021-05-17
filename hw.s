BITS 64

SECTION .text
global main

main:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel $+hello-$]
    mov rdx, [rel $+len-$]
    syscall
    
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    
    push 0x0000000000401050
    ret

hello: db "hello world", 33, 10
len: dd 13

