.data
.align 2
packet: 
.byte 0x18 0x00 0x9A 0x50 0x00 0x10 0x52 0x07 0x59 0xA1 0xDA 0x02 0x47 0x72 0x61 0x63 0x65 0x20 0x4D 0x75 0x72 0x72 0x61 0x79
v0: .asciiz "v0: "

.text
.globl main
main:
la $s0, packet 
move $a0, $s0
jal compute_checksum
move $s0, $v0

la $a0, v0
li $v0, 4
syscall

move $a0, $s0
li $v0, 1
syscall

li $a0, '\n'
li $v0, 11
syscall

li $v0, 10
syscall

.include "proj4.asm"

