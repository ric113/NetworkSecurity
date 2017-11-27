#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

void magic(){
	char flag[50];
	puts("Congrats");
	
	FILE *fp = fopen("flag", "r");
	memset(flag, 0, sizeof(flag));
	fread(flag, 1, sizeof(flag), fp);
	fclose(fp);

	puts(flag);
	exit(-1);
}

int main(){
	char buf[55];
	gets(buf);
	return 0;
}
