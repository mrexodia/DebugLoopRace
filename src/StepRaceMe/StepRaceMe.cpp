#include <Windows.h>
#include <cstdio>

#define EXPORT extern "C" __declspec(dllexport)

EXPORT volatile unsigned int RaceCounter = 0;
EXPORT volatile unsigned int ControlCounter = 0;
EXPORT volatile unsigned int Control2Counter = 0;

// RaceFunction lives in its own code section so it lands on its own page. A memory
// breakpoint guards a whole page, so this keeps the guard off the control functions
// and main() code (which are in .text) when testing execute-type memory breakpoints.
// Distinct bodies so /OPT:ICF cannot fold them to one address.
EXPORT __declspec(code_seg("racepage")) __declspec(noinline) void RaceFunction()
{
    InterlockedIncrement(&RaceCounter);
}

// Control points: the debugger arms single-steps here (on two different threads).
EXPORT __declspec(noinline) void ControlFunction()
{
    InterlockedExchangeAdd((volatile LONG*)&ControlCounter, 7);
}

EXPORT __declspec(noinline) void Control2Function()
{
    InterlockedExchangeAdd((volatile LONG*)&Control2Counter, 5);
}

// Workers spin on RaceFunction forever; main runs briefly then exits WITHOUT joining
// them. Returning from main() calls ExitProcess, which force-terminates the still-
// spinning worker threads. Some of them are terminated while the debugger is in the
// middle of their breakpoint step-over - exactly the condition that triggers the
// hardware breakpoint reset race (a thread being processed exits mid-step-over).
static DWORD WINAPI Worker(LPVOID)
{
    Sleep(80);
    for (;;)
    {
        RaceFunction();
        Sleep(1); // throttle so the debugger keeps up with the slow hw-bp step-over
    }
    return 0;
}

static DWORD WINAPI Stepper(LPVOID)
{
    Sleep(40);
    Control2Function();     // second control point, on this thread
    for (;;)
        Sleep(1);
    return 0;
}

int main()
{
    puts("[DebugMe] Hello debugger!");
    RaceFunction();

    for (int i = 0; i < 5; i++)
        CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, Stepper, nullptr, 0, nullptr);

    ControlFunction(); // control point on the main thread
    Sleep(600);        // let the workers race and build up a step-over backlog

    printf("[DebugMe] RaceCounter: %u  Control: %u  Control2: %u\n", RaceCounter, ControlCounter, Control2Counter);
    return 0; // ExitProcess terminates the spinning workers mid-step-over
}
