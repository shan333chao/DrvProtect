#include <Windows.h>
#include <stdio.h>
#include "Caller.h"
#include <random>
int main() {
 

	ULONG result= caller::InstallDriver();
	printf("%s \r\n",result);
 

	getchar();
	return 0;

}