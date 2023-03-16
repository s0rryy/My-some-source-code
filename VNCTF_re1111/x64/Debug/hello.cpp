#include <stdio.h>
#include <windows.h>
int main() {
	int time = 0;
	while (true)
	{
		printf("hellow time: %d\n", time);
		Sleep(1000);
		time++;
	}
	return 0;
}