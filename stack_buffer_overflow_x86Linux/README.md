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
+ **Word:** ` \xAA\xBB\xCC\xDD`
+ **Address:**  `0xffff0000`

| Memory address | 0xffff0000 | 0xffff0001 | 0xffff0002 | 0xffff0003 |
|:---:|:---:|:---:|:---:|:---:|
| Big endian | AA | BB | CC | DD |
| Lil endian | DD | CC | BB | AA |

# Take control of EIP 


















