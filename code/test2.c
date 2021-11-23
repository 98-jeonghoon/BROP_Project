#include <stdio.h>
#include <unistd.h>
#include <string.h>

int toggle = 0;

void vuln()
{
	char buf[405];

	read(0, buf, 0x1000);

	if(strlen(buf) == 39842)
		toggle = 1;	
}
void main()
{
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 1, 0);

	printf("what do you want?\n");
	vuln();
	printf("gachon\n");

	if(toggle)
		printf("what?\n");
}
