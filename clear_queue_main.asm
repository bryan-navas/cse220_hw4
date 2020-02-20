.data
.align 2
max_queue_size: .word 7
queue:  # random garbage
.half 4829  # size
.half 8383  # max_size
.word 0x0359ecda, 0x11219f6d, 0x0594776c, 0x313694e0, 0x1a103fc2, 0x110f37bd, 0x06e48f83

.text
.globl main
main:
la $a0, queue
lw $a1, max_queue_size
jal clear_queue

# You will need to write your own code here to check the contents of the queue.

move $a0, $v0 
li $v0, 1
syscall

li $v0, 10
syscall

.include "proj4.asm"
