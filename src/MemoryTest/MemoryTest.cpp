#include <iostream>
#include <Windows.h>
#include <atomic>

#define EXPORT extern "C" __declspec(dllexport)

#pragma section(".memrw", read, write)


__declspec(allocate(".memrw"))
EXPORT char HelloWorld[0x4000] = "Hello";

int main()
{
	puts("[DebugMe] Hello debugger!");

	char buffer[256];
	for (int i = 0; i < 6; i++)
		buffer[i] = HelloWorld[i];
	puts(buffer);

	return 0;
}
