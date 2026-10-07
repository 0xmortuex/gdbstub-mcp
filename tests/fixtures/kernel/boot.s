# Multiboot v1 header + entry for the gdbstub-mcp test kernel.
.set MAGIC, 0x1BADB002
.set FLAGS, 0x0
.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long -(MAGIC + FLAGS)

.section .bss
.align 16
stack_bottom:
.skip 8192
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp
    call kmain
1:  hlt
    jmp 1b
