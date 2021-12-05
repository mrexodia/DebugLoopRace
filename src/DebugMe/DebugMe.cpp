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
    for(int i = 0; i < 1000; i++)
        RaceFunction();
    printf("[DebugMe] RaceCounter: %u\n", RaceCounter);
    return 0;
}
