#include <stdio.h>

void main()
{
	int n;

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	printf("what do you want?\n");
	scanf("%d", &n);

	if(n == 3039)
		printf("GOOD!\n");
	else
		printf("NO!\n");
}
