#include <cstdio>
#include <cstdlib>

#include "TitanEngine.h"

static PROCESS_INFORMATION pi;
static ULONG_PTR raceFunction = 0;
static ULONG_PTR raceCounter = 0;
static unsigned int breakpointHitCounter = 0;
static unsigned int expectedHitCounter = 0;

static void cbBreakpoint()
{
	const auto& exception = ((DEBUG_EVENT*)GetDebugData())->u.Exception;
	auto breakpointAddress = (ULONG_PTR)exception.ExceptionRecord.ExceptionAddress;
	printf("Hit breakpoint %p\n", breakpointAddress);
	breakpointHitCounter++;
}

static void cbCreateProcess(CREATE_PROCESS_DEBUG_INFO* CreateProcessInfo)
{
	puts("cbCreateProcess");

	const auto& process = *CreateProcessInfo;
	if (process.hFile)
	{
		wchar_t szFilePath[MAX_PATH] = L"";
		GetFinalPathNameByHandleW(process.hFile, szFilePath, _countof(szFilePath), VOLUME_NAME_DOS);

		printf("file: %S\n", szFilePath);

		CloseHandle(process.hFile);

		auto base = ULONG_PTR(process.lpBaseOfImage);
		auto hLib = LoadLibraryExW(szFilePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
		if (hLib)
		{
			raceFunction = ULONG_PTR(GetProcAddress(hLib, "RaceFunction"));
			raceFunction -= ULONG_PTR(hLib);
			raceFunction += base;

			raceCounter = ULONG_PTR(GetProcAddress(hLib, "RaceCounter"));
			raceCounter -= ULONG_PTR(hLib);
			raceCounter += base;

			FreeLibrary(hLib);
		}

		printf("RaceFunction: %p, RaceCounter: %p\n", raceFunction, raceCounter);

		//SetBPX(ULONG_PTR(process.lpStartAddress), UE_BREAKPOINT, (void*)cbBreakpoint); // entry breakpoint (for testing)
		SetBPX(raceFunction, UE_BREAKPOINT, (void*)cbBreakpoint);
	}
}

static void cbExitProcess(EXIT_PROCESS_DEBUG_INFO* ExitProcess)
{
	SIZE_T temp = 0;
	ReadProcessMemory(pi.hProcess, (LPVOID)raceCounter, &expectedHitCounter, sizeof(expectedHitCounter), &temp);

	puts("cbExitProcess");
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 2)
	{
		puts("Usage: TestTitanEngine my.exe");
		return EXIT_FAILURE;
	}
	auto pi = (PROCESS_INFORMATION*)InitDebugW(argv[1], nullptr, nullptr);
	if (pi == nullptr)
	{
		puts("InitDebugW failed");
		return EXIT_FAILURE;
	}
	::pi = *pi;
	SetCustomHandler(UE_CH_CREATEPROCESS, (void*)cbCreateProcess);
	SetCustomHandler(UE_CH_EXITPROCESS, (void*)cbExitProcess);
	DebugLoop();

	printf("breakpointHitCounter: %d == %d (%s)\n", breakpointHitCounter, expectedHitCounter, breakpointHitCounter == expectedHitCounter ? "GOOD" : "BAD");
}