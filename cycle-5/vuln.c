// Steven Comer
// CSC 791: Special Topics in Software Exploitation
// Cycle 5: Protection Bypass of NX with ret2libc
// Contents: Simple C program vulnerable to buffer overflow
// Modified: 6 May 2016

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
	char buffer[1024];
	read(0,buffer,1050);
	printf("sh; ");
	printf("Buffer: %s\n", buffer);
	fflush(stdout);
	return 0;
}
