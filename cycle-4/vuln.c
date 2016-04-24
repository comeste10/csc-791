# Steven Comer
# CSC 791: Special Topics in Software Exploitation
# Cycle 4: Protection Bypass of ASLR and NX
# Contents: Simple C program vulnerable to buffer overflow
# Modified: 24 April 2016

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
	char buffer[1024];
	if(argc==2) {
		strcpy(buffer,argv[1]);
	}
	else {
		system("/bin/false");
	}
}
