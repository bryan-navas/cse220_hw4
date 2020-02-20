# CSE 220 Programming Project #4
# Bryan Navas
# bnavas
# 112244631

#################### DO NOT CREATE A .data SECTION ####################
#################### DO NOT CREATE A .data SECTION ####################
#################### DO NOT CREATE A .data SECTION ####################

.text

compute_checksum: 
    #$a0 will contain packet address
    
    #(version + msg id + total length + 
    #priority + flags + protocol + frag offset + 
    #src addr + dest addr) mod 2^16
    
    li $t0, 0          #this will contain our running total
    lw $t1, 0($a0)     #$t1 now contains the bits to version, msg ID, and total length
    andi $t2, $t1, 0xF0000000     #this operation grabs the 4bits of the version
    srl $t2, $t2, 28
    add $t0, $t0, $t2    #running sum =+ version
    andi $t2, $t1, 0xFFF0000     #this grabs the 12 bits of the msg_ID
    srl $t2, $t2, 16
    add $t0, $t0, $t2    #running sum =+ msg_ID
    andi $t2, $t1, 0xFFFF    #grabs the last 16bits which is length 
    add $t0, $t0, $t2    #running sum =+ total_length
    
    lw $t1, 4($a0)   #t1 now contains priority, flags, protocol, and fragment offset
    andi $t2, $t1, 0xFF000000    #grabs the 8 bits that contains priority
    srl $t2, $t2, 24
    add $t0, $t0, $t2     #running sum =+ priority
    andi $t2, $t1, 0xC00000      #grabs the 2 bits that contain the flag
    srl $t2, $t2, 22
    add $t0, $t0, $t2     #running sum =+ flag
    andi $t2, $t1, 0x3FF000    #grabs the 10 bits that contain protocol
    srl $t2, $t2, 12  
    add $t0, $t0, $t2     #running sum =+ protocol
    andi $t2, $t1, 0xFFF      #grabs the last 12 bits that contain frag_offset
    add $t0, $t0, $t2     #running sum =+ fragment offset
    
    lw $t1, 8($a0)  #$t1 now contains checksum, source_addr, and dest_addr
    andi $t2, $t1, 0xFF00     #grabs second to last 8bits that contain src_addr
    srl $t2, $t2, 8
    add $t0, $t0, $t2     #running sum =+ src_addr
    andi $t2, $t1, 0xFF       #grabs the last 8 bits that contains dest_addr
    add $t0, $t0, $t2     #running sum =+ dest_addr
    
    li $t2, 65536   #$t2 is 2^16
    div $t0, $t2    #to get modulo 2^16
    mfhi $v0
    
    jr $ra

compare_to:
    #$a0 will contain packet 1
    #$a1 will contain packet 2
    
    lw $t1, 0($a0)     #$t1 now contains the bits to version, msg ID, and total length of PACKET 1
    lw $t2, 0($a1)     #$t2 now contains the bits to version, msg ID, and total length of PACKET 2
    andi $t3, $t1, 0xFFF0000     #this grabs the 12 bits of the msg_ID for packet 1
    srl $t3, $t3, 16
    andi $t4, $t2, 0xFFF0000    #this grabs the 12 bits of the msg_ID for packet 2
    srl $t4, $t4, 16
    
    blt $t3, $t4, return_neg1    #if p1.msg_id < p2.msg_id then return -1
    bgt $t3, $t4, return_one     #else if p1.msg_id > p2.msg_id then return 1
    
    #now we compare the frag_offsets IF the ID's are equal
    lw $t1, 4($a0)   #t1 now contains priority, flags, protocol, and fragment offset of PACKET 1
    lw $t2, 4($a1)   #t2 now contains priority, flags, protocol, and fragment offset of PACKET 2
    andi $t3, $t1, 0xFFF      #grabs the last 12 bits that contain frag_offset for PACKET 1
    andi $t4, $t2, 0xFFF      #grabs the last 12 bits that contain frag_offset for PACKET 2
    
    blt $t3, $t4, return_neg1   #if p1.frag < p2.frag then return -1
    bgt $t3, $t4, return_one    #else if p1.frag > p2.frag then return 1
    
    #now we compare the source_addr's since the fragment_offsets are also the same
    lw $t1, 8($a0)  #$t1 now contains checksum, source_addr, and dest_addr of PACKET 1
    lw $t2, 8($a1)  #$t1 now contains checksum, source_addr, and dest_addr of PACKET 2
    andi $t3, $t1, 0xFF00     #grabs second to last 8bits that contain src_addr in PACKET 1
    srl $t3, $t3, 8
    andi $t4, $t2, 0xFF00     #grabs the second to last 8 bits that contain src_addr in PACKET 2
    srl $t4, $t4, 8
    
    blt $t3, $t4, return_neg1   #if p1.src_addr < p2.src_addr return -1
    bgt $t3, $t4, return_one    #else if p1.src_addr > p2.src_addr return 1            
    
    #if the message_ID, fragment_offset, AND src_address are the SAME, this code runs and returns 0
    j return_zero
    
    return_neg1:
    li $v0, -1
    jr $ra
    
    return_zero:
    li $v0, 0
    jr $ra
    
    return_one:
    li $v0, 1
    jr $ra

packetize:
    #$a0 packet_data (large buffer where we will write to)
    #$a1 msg (the null terminated string where we will write to)
    #$a2 payload_size (number of character to extract from packet's payload
    #$a3 version
    #0($sp) msg_id
    #4($sp) priority
    #8($sp) protocol
    #12($sp) src_addr
    #16($sp) dest_addr
    
    lw $t0, 0($sp)       #temporaries to store args from stack
    lw $t1, 4($sp)
    lw $t2, 8($sp)
    lw $t3, 12($sp)
    lw $t4, 16($sp)
    
    addi $sp, $sp, -60  
    sw $s0, 0($sp)	#packet
    sw $s1, 4($sp)	#msg
    sw $s2, 8($sp)	#payload_size
    sw $s3, 12($sp)	#version
    sw $s4, 16($sp)	#msg_id
    sw $s5, 20($sp)	#priority
    sw $s6, 24($sp)	#protocol
    sw $s7, 28($sp)	#src_addr
    sw $ra, 48($sp)
    
    move $s0, $a0
    move $s1, $a1
    move $s2, $a2
    move $s3, $a3
    move $s4, $t0
    move $s5, $t1
    move $s6, $t2
    move $s7, $t3
    sw $t4, 32($sp)	#dest_addr
    
    li $t0, 0       #size tracker 
    move $t1, $s1   #moving msg_addr to $t1, to iterate 
    countChars_loop:
    	lbu $t2, 0($t1)  #loads a char from message
    	addi $t0, $t0, 1   #adds 1 to our counter everytime 
    	beqz $t2, countChars_loop.end   #the null terminator has to be counted
    	addi $t1, $t1, 1  #iterates through the word
    j countChars_loop
    countChars_loop.end:
    
    #calculating how many packets there will be:
    div $t0, $s2     #(msg.length) / (payload_size)
    mflo $t1         #the quotient
    sw $t1, 56($sp)
    mfhi $t2  	     #the remainder also how many extra chars left over
    sw $t2, 52($sp)  #stores remainder
    
    beqz $t2, skipAddOnePacket   #if it is the "perfect" amount, all packets will have payload_size
    addi $t1, $t1, 1
    sw $t1, 56($sp)
    skipAddOnePacket:   #if there is a remainder it means the last packet will have less than payload length
    			#this is another way to write Math.ceil(msg.length / payload_size)
 			
    sw $t1, 36($sp)     #36($sp) will now hold how many times the loop will run(number of packets to make)
    li $t0, 0
    sw $t0, 40($sp)     #40($sp) will hold the loop counter
    sw $t0, 44($sp)     #44($sp) will hold fragment_offset counter
    packetizeLoop:
    	lw $t0, 36($sp)
    	lw $t1, 40($sp)
    	beq $t0, $t1, packetizeLoop.end #ends the loop when counter == num packets
    	
    	#calculating total_length
    	li $t0, 12
    	add $t0, $t0, $s2    #total_length = 12 + payload_size
    	#setting up the first word, total_length + id + version
    	move $t1, $s4       #grabs msg_id
    	sll $t1, $t1, 16    #puts msg_id in bits 16-27
    	move $t2, $s3       #grabs version
    	sll $t2, $t2, 28    #puts it in the last 4bits
    	add $t0, $t0, $t1
    	add $t0, $t0, $t2   #this contains the first word of the packet
    	#setting up the second word, fragment_offset + protocol + flags + priority
    	lw $t1, 44($sp)    #grabs frag_offset from stack
    	move $t2, $s6      #grabs protocol
    	sll $t2, $t2, 12   #shifts it left by 12
        li $t3, 1          #flag is 1
        sll $t3, $t3, 22   #shifts it left by 22
        move $t4, $s5      #grabs priority
        sll $t4, $t4, 24   #shifts it by 24
        add $t1, $t1, $t2
        add $t1, $t1, $t3
        add $t1, $t1, $t4  #this contains the second word of the packet
        #setting up the third word, src_addr + dest_addr + checksum
        lw $t2, 32($sp)    #gets dest_addr
        move $t3, $s7      #grabs src_addr
        sll $t3, $t3, 8  	   #shifts it to the left by 8 
        add $t2, $t2, $t3  #this contains the third word of the packet
        
    	sw $t0, 0($s0)
    	sw $t1, 4($s0)
    	sw $t2, 8($s0)   #this writes the 12 bytes of every packet, with checksum being 0
    	
    	addi $sp, $sp, -4
    	sw $t2, 0($sp)      #stores the third word of the packet
    	
    	move $a0, $s0
    	jal compute_checksum
    	#$v0 now contains checksum
    	
    	lw $t2, 0($sp)     #gets back the third word of the packet
    	addi $sp, $sp, 4
    	
    	sll $v0, $v0, 16  #shifts checksum to the left by 16
    	add $t2, $t2, $v0 #adds checksum to that
    	sw $t2, 8($s0)    #rewrites using the correct checksum
    	
    	#here we actually write the payload
    	li $t0, 0   #loop counter
    	move $t3, $s1  #temp addr for msg
    	move $t4, $s0  #temp for big packet addr
    	writingPayload:
    	beq $t0, $s2, writingPayload.end
    	lbu $t1, 0($t3) #grabs a char from the message
    	
    	sb $t1, 12($t4)   #stores the char from message into packet payload (12 offset bc header)
    	beqz $t1, writingPayload.end  #when it reaches the NT, end the writing loop		
    	addi $t3, $t3, 1   #adds 1 to msg_addr
    	addi $t0, $t0, 1   #adds 1 to loop counter
    	addi $t4, $t4, 1   #adds 1 to big packet addr
    	j writingPayload
    	writingPayload.end:
    	 	 	
    		
    	lw $t1, 44($sp)    #grabs frag_offset from stack
    	add $t1, $t1, $s2  #current frag_offset + payload size
    	sw $t1, 44($sp)    #puts the newly incremented frag_offset into the stack
    	add $s1, $s1, $s2	#adds payload_size to msg_addr
    	
    	li $t0, 12
    	add $t0, $t0, $s2  		#this is total length
    	add $s0, $s0, $t0		#also add to main buffer addr (+ total length)
    	lw $t0, 40($sp)
    	addi $t0, $t0, 1     #adds 1 to the counter, puts it back on stack
    	sw $t0, 40($sp)
    j packetizeLoop
    packetizeLoop.end:
    
    
    lw $t9, 52($sp)   #how many words in last packet
    beqz $t9, skipNewLength    #if last packet is size of payload
    
    li $t0, 12
    add $t9, $t0, $s2   #this is total length
    sub $s0, $s0, $t9   #subtracting total length from main buffer
    lw $t0, 0($s0)  #this word holds the total length, msg_id, and version
    srl $t0, $t0, 16
    sll $t0, $t0, 16    #this makes total_legnth 0
    #the new total length for the last packet will be total_length -( payload_size-size of msg)
    lw $t3, 52($sp)  #gets length of last word
    sub $t3, $s2, $t3    # $t3 = payload_size - size of last payload
    sub $t9, $t9, $t3    #the new totalsize for the last packet
    add $t0, $t0, $t9    #the new word holding the right total_length
    sw $t0, 0($s0)       #stores the new word with the right total_length
    
    skipNewLength:
    lw $t0, 4($s0)   #loads the second word of the last packet (frag_offset, protocol, flags, priority)
    andi $t0, $t0, 0xFF3FFFFF     #makes the flags 0
    sw $t0, 4($s0)   #stores it back
    
    move $a0, $s0
    jal compute_checksum
    #$v0 now has checksum
    
    lw $t0, 8($s0)  #loads the third word of last packet
    sll $v0, $v0, 16   #shifts checksum to the right place
    sll $t0, $t0, 16   #gets rid of old check sum
    srl $t0, $t0, 16
    add $t0, $t0, $v0
    sw $t0, 8($s0)   #stores the new checksum
    
    
    #PUT THE STACK BACK 
    lw $v0, 56($sp)
    lw $ra, 48($sp)
    
    
    lw $s0, 0($sp)	#packet
    lw $s1, 4($sp)	#msg
    lw $s2, 8($sp)	#payload_size
    lw $s3, 12($sp)	#version
    lw $s4, 16($sp)	#msg_id
    lw $s5, 20($sp)	#priority
    lw $s6, 24($sp)	#protocol
    lw $s7, 28($sp)	#src_addr
    addi $sp, $sp, 60  
    jr $ra
clear_queue:
    #$a0 has queue
    #$a1 has max_queue_size
    
    bltz $a1, returnNeg1CQ  #returns -1 if max_queue_size is less than 0
    
    #set size of PQ to 0 and set max_size to param
    #assign 0 to all max_size elems
    
    li $t0, 0
    add $t0, $t0, $a1     #this makes it so that max_size is in lower half of word
    sw $t0, 0($a0)   #sets size and max_size to 0
    addi $a0, $a0, 4  #skips the first 2 half words of struct to get to the juicy meat that is the Packet[]
    
    li $t0, 0  #loop counter
    setZerosLoop:
    beq $t0, $a1, setZerosLoop.end
    
    sw $zero, 0($a0)    #stores a 0 in this packet
    
    addi $t0, $t0, 1    #counter++
    addi $a0, $a0, 4    #adds a word to the queue addr
    j setZerosLoop
    setZerosLoop.end: 
    li $v0, 0
    jr $ra

    returnNeg1CQ:
    li $v0, -1
    jr $ra
enqueue:
    #$a0 will hold queue
    #$a1 will hold packet   
    lw $t0, 0($a0)   #loads the word that has size and max_size
    sll $t1, $t0, 16       #now size is in uppper half of word
    srl $t1, $t1, 16       #size is in lower half starting with all 0's
    move $t3, $t1          #holds size which we will use for current index later
    srl $t2, $t0, 16       #now max_size is also in lower half of word
    bge $t1, $t2, enqueue.max   #exits the function when it is at max
    
    
    addi $sp, $sp, -32
    sw $ra, 0($sp) 
    sw $s0, 4($sp)
    sw $s1, 8($sp)
    sw $s2, 16($sp)
    sw $s3, 20($sp)
    sw $s4, 24($sp)
    sw $s5, 28($sp)
   
    addi $t1, $t1, 1    #size++
    move $s5, $t1    #holds new size for return
    sll $t2, $t2, 16    #shifts max_size so that it is in upper hald of word
    add $t1, $t1, $t2   #places size in lower hald; max_size in upper_half
    sw $t1, 0($a0)      #stores the new size in the queue
    addi $a0, $a0, 4    #adds a word so now the base addr is the base of the packet array
    
    #placing current packet into queue[size]
    sll $t4, $t3, 2    # i being [size]*4
    add $t0, $a0, $t4  #addr = base_addr + i*4
    sw $a1, 0($t0)     #stores the packet in queue[size]
    
    #addr = base_addr + 4 * i	
    #parent node = floor((i-1)/2)
    move $s0, $a0      #$s0 will now hold the array of packets (after adding +4 to base_addr of queue)
    move $s1, $t3      #$s1 (current index) holds the index of the packet we're trying to insert (starts at queue[size]
    #$s3 will hold current packet
    #$s4 will hold parent packet
    #$s5 holds new size
    #$s6 previous index
    enqueueLoop:
    sll $t1, $s1, 2      #$t1 = current index * 4
    add $t0, $s0, $t1    #$t0 = base_addr + current_index*4
    lw $t2, 0($t0)       #current packet addr
    move $s3, $t2        #saves current packet addr
    
    #calculate parent index
    move $s6, $s1        #previous index
    addi $s1, $s1, -1    #(i-1)
    li $t3, 2
    div $s1, $t3         # (i-1)/2
    mflo $t3             #quotient of that ^ stored in $t3 (parent node)
    move $s1, $t3        #sets the new index to the parent. so if they swap, that parent will be packet to insert
    
    #parent index in $t3
    sll $t4, $t3, 2     #$t4 = parent index *4
    add $t0, $s0, $t4   #$t0 = base_addr + parent_index*4
    lw $t5, 0($t0)      #parent packet addr
    move $s4, $t5	#saves parent addr
    
    move $a0, $s3       #current packet
    move $a1, $s4	#parent packet
    jal compare_to
    #v0 contains -1 if current is less than 2
    #0 if the packets are equal
    #1 if current is greater than parent
    li $t0, -1
    bne $v0, $t0, breakEnqueueLoop   #breaks when it's greater than or equal to ( 0 or 1)
     
    swap:
    #we know packet 1 is less than packet 2
    move $t0, $s4     #temp = parent packet address
    #s1 holds parent index
    #s6 holds child index
    sll $t2, $s1, 2   #parent index *4
    add $t1, $s0, $t2    #base_addr + parentI*4
    sw $s3, 0($t1)    # parent -> child // store the current packet in parent packet
    
    sll $t2, $s6, 2   #child index *4
    add $t1, $s0, $t2   #base_addr + childI*4
    sw $t0, 0($t1)    # child - > parent // store the parent packet in the current packet
    
    
    j enqueueLoop
    enqueueLoop.end:
    
    breakEnqueueLoop:
    
    #PUT BACK THE STACK
    move $v0, $s5   #loads new size
    
    lw $ra, 0($sp)
    lw $s0, 4($sp)
    lw $s1, 8($sp)
    lw $s2, 16($sp)
    lw $s3, 20($sp)
    lw $s4, 24($sp)
    lw $s5, 28($sp)
    addi $sp, $sp, 32
    jr $ra
    enqueue.max:
    move $v0, $t2    #returns queue.max_size when it is full
    jr $ra

dequeue:
    #$a0 contains queue
    lw $t0, 0($a0)    #loads the word that has size and max_size
    sll $t1, $t0, 16       #now size is in uppper half of word
    srl $t1, $t1, 16       #size is in lower half starting with all 0's
    
    blez $t1, returnEmpty   #if the queue is 0 then it returns 0
    srl $t2, $t0, 16      #gets rid of the size
    sll $t2, $t0, 16      #now there is a 0 for size
    addi $t1, $t1, -1      #size--
    add $t2, $t2, $t1     #setting the right size
    sw $t2, 0($a0)        #stores the newly incremented size in queue
    
    addi $sp, $sp, -48
    sw $s0, 0($sp)	#holds packet[] address
    sw $s1, 4($sp)	#holds new size after decrease
    sw $s2, 8($sp)	#hold the packet we will return
    sw $s3, 16($sp)	#current left child
    sw $s4, 20($sp)	#current right child	
    sw $s5, 28($sp)     #smaller of the 2 children
    sw $s6, 32($sp)	#current index
    sw $s7, 36($sp)	#smaller child address
    #40($sp)		#holds index
    sw $ra, 44($sp)
    
    addi $a0, $a0, 4    #adds 4 so now the addr points to array of packets
    move $s0, $a0       #$s0 holds the addr to the packets
    move $s1, $t1       #$s1 holds the new size of the struct
    bnez $s1, moreThanOnePacket   #if new size is 0, then there was only one packet, if not eqz then multiple packets
    OnePacketToRemove:
    	lw $v0, 0($s0)     #the first and only packet is at index 0 of the struct
        sw $0, 0($s0)     #after removing it we set it to 0 so that it indicates the packet it removed
    	j dequeue.end
    moreThanOnePacket:
    #now we will swap the last packet for the first one	
    	#addr = base_addr + 4*i
    	sll $t0, $s1, 2    #used to get index of Queue[size-1]
    	add $t1, $s0, $t0  # base_addr + 4*i
    	lw $t0, 0($t1)     #this loads in the last packet
    	lw $s2, 0($s0)     #this is the address of the first packet
    	sw $0, 0($t1)      #this zeroes out the packet to indicate that it was removed
    	sw $t0, 0($s0)     #this places the last index in index 0
    	li $s6, 0    	   #sets the current index of the swapped node to 0
    siftDownLoop:	
    #now we are going to get the values of the left and right children and compare to check the smaller of the two
    	#getting left child
    	sll $t0, $s6, 1    #current i * 2
    	addi $t0, $t0, 1   #2i+1
    	bge $t0, $s1, siftDownBreak     #if the index calculated is greater than or equal to new size, break
    	sll $t1, $t0, 2    #$t1 = (2i+1)*4
    	add $t1, $s0, $t1  #addr = base_addr + (2i+1)*4
    	lw $s3, 0($t1)     #$s3 = current left child (packet addr)
    	#getting right child
    	sll $t0, $s6, 1   #current i * 2
    	addi $t0, $t0, 2  #2i +2
    	sll $t1, $t0, 2   #$t1 =(2i+2)*4
    	add $t1, $s0, $t1 #addr = base_addr + (2i+2)*4
    	lw $s4, 0($t1)    #$s4 = current right child
    #after getting the left and right child we will compare the two
    	move $a0, $s3  
    	move $a1, $s4
    	jal compare_to
    	#v0 contains -1 if left is less than right
   	#0 if the packets are equal
    	#1 if left is greater than right
    #we will now compare the smaller child to the current one
    li $t0, 1
    beqz $v0, swapLeftCurrent   #if both the children are equal, swap current with left
    beq $v0, $t0, rightSmaller     #if left if greater than rigth, right is smaller
    	leftSmaller:
    	move $s5, $s3    #$s5 holds the smaller child, left child in this case
    	sll $t0, $s6, 1    #current i * 2
    	addi $t0, $t0, 1   #2i+1
    	sw $t0, 40($sp)    #stores the index of left
    	sll $t1, $t0, 2    #$t1 = (2i+1)*4
    	add $s7, $s0, $t1  #addr = base_addr + (2i+1)*4  addr of smaller child in s7
    	j compareCurrentWithSmallestChild	
    	rightSmaller:
    	move $s5, $s4    #$s5 holds the smaller child, right child in this case
    	sll $t0, $s6, 1   #current i * 2
    	addi $t0, $t0, 2  #2i +2
    	sw $t0, 40($sp)   #stores the index of right
    	sll $t1, $t0, 2   #$t1 =(2i+2)*4
    	add $s7, $s0, $t1 #addr = base_addr + (2i+2)*4
    	compareCurrentWithSmallestChild:
    		#first we get the current packet
    		sll $t0, $s6, 2    #i*4
    		add $t0, $s0, $t0  #base_addr + 4*i
    		lw $a0, 0($t0)   #sets a0 to the current packet
    		move $a1, $s5   #sets a1 to smallest out of 2 children
    		jal compare_to
    		#$v0 will contain -1 if current is less than smallest child
    		bltz $v0, siftDownBreak    #BREAKCASE: if current is less than smallest of 2 children
    		#else, if not a breakCase, we swap with the lesser child and update current index
    			#getting current packet
    			sll $t0, $s6, 2    #i*4
    			add $t0, $s0, $t0  #base_addr + 4*i
    			lw $t1, 0($t0)   #sets t1 to the current packet
    			#remember smallest child packet is already in $s5
    			move $t2, $t1    #temp = current packet
    			sw $s5, 0($t0)   #sets current packet to smaller child
    			sw $t2, 0($s7)   #smaller child = temp(current packet)
    			lw $s6, 40($sp)  #sets the index to whereever it got swapped	
    		j siftDownLoop
    	swapLeftCurrent:
    		#getting current packet
    		sll $t0, $s6, 2    #i*4
    		add $t6, $s0, $t0  #base_addr + 4*i
    		lw $t5, 0($t6)   #sets t1 to the current packet	
    		#get left packet
    		sll $t0, $s6, 1    #current i * 2
    		addi $t0, $t0, 1   #2i+1
    		sll $t1, $t0, 2    #$t1 = (2i+1)*4
    		add $t1, $s0, $t1  #gets addr
    		lw $t2, 0($t1)     #left packet
    		move $t3, $t5   #temp = current packet
    		sw $t2, 0($t6)  #current = leftt packet
    		sw $t3, 0($t1)  #left = temp(current packet)
    		
    		sll $s6, $s6, 1  #2i
    		addi $s6, $s6, 1 #2i+1
    
    j siftDownLoop	
    siftDownLoop.end:	
    siftDownBreak:	
    	
    
    dequeue.end:
    lw $ra, 44($sp)
    move $v0, $s2     #moves the removed packet to $v0
    jr $ra
    
    returnEmpty:
    li $v0, 0
    jr $ra

assemble_message:
    jr $ra


#################### DO NOT CREATE A .data SECTION ####################
#################### DO NOT CREATE A .data SECTION ####################
#################### DO NOT CREATE A .data SECTION ####################
