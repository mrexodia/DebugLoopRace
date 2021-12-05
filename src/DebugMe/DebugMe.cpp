#include <iostream>
#include <Windows.h>
#include <atomic>

#define EXPORT extern "C" __declspec(dllexport)

EXPORT volatile unsigned int RaceCounter = 0;

EXPORT __declspec(noinline) void RaceFunction()
{
	InterlockedIncrement(&RaceCounter);
}

int main()
{
	puts("[DebugMe] Hello debugger!");
	RaceFunction();
	Sleep(200);
	puts("[DebugMe] Racing...");
	HANDLE handles[5] = {};
	for (int i = 0; i < _countof(handles); i++)
	{
		handles[i] = CreateThread(nullptr, 0, [](LPVOID)->DWORD
		{
			Sleep(100);
			for (int i = 0; i < 1000; i++)
				RaceFunction();
			return 0;
		}, nullptr, 0, nullptr);
	}
	WaitForMultipleObjects(_countof(handles), handles, TRUE, INFINITE);
	for (int i = 0; i < _countof(handles); i++)
	{
		if (handles[i])
		{
			CloseHandle(handles[i]);
		}
	}
	printf("[DebugMe] RaceCounter: %u\n", RaceCounter);
	return 0;
}
