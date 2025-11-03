# Buffer Overflows Overview
- __buffer overflows__ are caused by __incorrect program code__, which cannot process too large amounts of data correctly by the CPU, therefore, __manipulate the CPU's processing__.

# Exploit Development Introduction
- __An exploit__ is a code that causes the service to perform an operation we want by __abusing the found vulnerability__

# CPU Architecture
## Memory
### Primary
- Cache n RAM 
### Second
- not directly to CPU but by I/0 
- is Hard drive, Flash, CD..
## CPU
- x86/i386 - (AMD & Intel)
- x86-64/amd64 - (Microsoft & Sun)
- ARM - (Acorn)
## Instruction Cycle
- __Fetch:__ next machine instruction address read from Instruction Address Register (IAR) and then loaded from Cache or RAM into Instruction Counter. The IAR I mostly remember is RIP ? which is stored 64 bytes (if I remember).
- __Decode:__ instruction decoder converts the instructions and starts the necessary circuits to execute the instruction.
- __Fetch operand:__ If further data have to be loaded for execution, these are loaded from the cache or RAM into the working registers
- __Execute:__ instruction is executed. 
- __Update Instruction Pointer:__ If no jump instruction has been executed in the EXECUTE phase, the IAR is now increased by the length of the instruction. 

# Stack-Based Buffer Overflow 
- __Modern memory protection(DEP, ASLR)__ gonna prevent the damage by buffer overflow,__(DEP) Data Execution Prevention__ mark region of memory is __Read-Only__. The read-only memory region is __where some user-input is stored__ (Example: The Stack), so the idea behind DEP was to __prevent users from uploading shellcode to memory and then setting the instruction pointer to the shellcode__. But it can be get around with __ROP (Return Oriented Programming)__. With ROP, the attacker needs to __know the memory addresses where things are stored__, so the defense against it was to implement __ASLR (Address Space Layout Randomization)__ which __randomizes where everything is stored__.

- For learning purpose we can disable ASLR by:
`sudo echo 0 > /proc/sys/kernel/randomize_va_space`
- To enable to let execute shellcode in stack, build binary with :
`gcc -fno-stack-protector -z execstack -o <Binary_file> <vuln_file.c>`
- I use this code (just copy from HTB lol): [vuln.c]

# CPU Register
I will link the Asembly Module later.

- __Endianess:__
+ __Big endian:__ highest valence -> low address 
+ __Little endian:__ lowest valence -> low address 

- Example:
+ Word: \xAA\xBB\xCC\xDD 
+ Address: 0xffff0000

| Mem address 	| 0xffff0000 	| 0xffff0001 	| 0xffff0002 	| 0xffff0003 	|
|-------------	|------------	|------------	|------------	|------------	|
| Big endian  	|     AA     	|     BB     	|     CC     	|     DD     	|
| Lil endian  	|     DD     	|     CC     	|     BB     	|     AA     	|

# Take control of RIP 
- First of all, let's look our vulnerable code snippet again. It gets a argument, store inside buffer and print Done message.
So we can add some "cheeses" to argument by overflow the buffer to `strcpy` function. There are some other not independently protected C functions like `gets`, `sprintf`, `scanf`,...so that `DEP` and `ASLR` should be used for safety. 
```#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bowfunc(char *string) {

	char buffer[1024];
	strcpy(buffer, string);
	return 1;
}

int main(int argc, char *argv[]) {

	bowfunc(argv[1]);
	printf("Done.\n");
	return 1;
}```

- What if we gave the argument the data more than 1024 bytes, let take 1200 bytes.The first 1024 bytes gonna go to buffer, the remain will overflow and stored outside, even overwrite the address of RIP (or whatever its sub register) pushed to stack. Without the DEP, we can inject the shellcode and then when the `ret` called ,shellcode executed. For my OS safety, I use the binary from the module.

![Alt text](/stack_overflow_check.png "Check if the buffer can be overflow")
Use the tools from `MSF`,we create a string
`/usr/share/metasploit-framework/tools/expoit/pattern_create.rb -l 1200 > pattern.txt` 
 and extract address from `RIP` to determine how many bytes to reach the `RIP`
`/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <address of RIP>`
In this binary, It took 1040 bytes to reach RIP (actually EIP cuz its i386 architecture)

# Determine the Length for shellcode
it can be useful to insert some no operation instruction (NOPS) before our shellcode begins so that it can be executed cleanly.
`NOPS` is "\x90".

# Identification of Bad Characters
Previously in UNIX-like operating systems, binaries started with two bytes containing a "magic number" that determines the file type. In the beginning, this was used to identify object files for different platforms. They can interfere our shellcode so we have to find all of them and check the shellcode

``CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\execstackf\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" ``

Brick by brick, we check calculate buffer and check bad character from CHARS.

