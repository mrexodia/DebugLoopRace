#include <map>
#include <Windows.h>

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		puts("Usage: DebugLoop my.exe");
		return EXIT_FAILURE;
	}
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessA(argv[1], nullptr, nullptr, nullptr, false, DEBUG_PROCESS, nullptr, nullptr, &si, &pi))
	{
		puts("CreateProcessA failed");
		return EXIT_FAILURE;
	}

	std::map<ULONG_PTR, unsigned char> breakpoints;
	ULONG_PTR raceFunction = 0, raceCounter = 0;

	int exitCode = EXIT_FAILURE;
	bool threadStepping = false;
	ULONG_PTR breakpointAddress = 0;
	for (bool continueDebugging = true; continueDebugging;)
	{
		DEBUG_EVENT debugEvent = {};
		if (!WaitForDebugEventEx(&debugEvent, INFINITE))
		{
			puts("WaitForDebugEventEx failed");
			break;
		}

		DWORD continueStatus = DBG_EXCEPTION_NOT_HANDLED;

		const char* eventNames[] =
		{
			"EXCEPTION_DEBUG_EVENT",
			"CREATE_THREAD_DEBUG_EVENT",
			"CREATE_PROCESS_DEBUG_EVENT",
			"EXIT_THREAD_DEBUG_EVENT",
			"EXIT_PROCESS_DEBUG_EVENT",
			"LOAD_DLL_DEBUG_EVENT",
			"UNLOAD_DLL_DEBUG_EVENT",
			"OUTPUT_DEBUG_STRING_EVENT",
			"RIP_EVENT",
		};

		printf("%s (%d)\n", eventNames[debugEvent.dwDebugEventCode - 1], debugEvent.dwDebugEventCode);

		switch (debugEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
			const auto& exception = debugEvent.u.Exception.ExceptionRecord;
			if (exception.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				breakpointAddress = (ULONG_PTR)exception.ExceptionAddress;
				auto breakpointItr = breakpoints.find(breakpointAddress);
				if (breakpointItr != breakpoints.end())
				{
					printf("Hit breakpoint %p\n", breakpointAddress);
					// restore original byte
					SIZE_T temp = 0;
					if (!WriteProcessMemory(pi.hProcess, LPVOID(breakpointAddress), &breakpointItr->second, 1, &temp))
					{
						puts("failed to restore original byte");
					}
					// set trap flag
					auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
					if (hThread)
					{
						CONTEXT context;
						context.ContextFlags = CONTEXT_CONTROL;
						GetThreadContext(hThread, &context);
						context.EFlags |= 0x100;
						//context.Rip = breakpointItr->first;
						SetThreadContext(hThread, &context);
						CloseHandle(hThread);
					}
					else
					{
						puts("OpenThread failed");
						continueDebugging = false;
					}
					threadStepping = true;
					continueStatus = DBG_CONTINUE;
				}
			}
			else if (exception.ExceptionCode == EXCEPTION_SINGLE_STEP && threadStepping)
			{
				printf("single step after breakpoint %p\n", breakpointAddress);
				// restore CC
				unsigned char breakpointByte = 0xCC;
				SIZE_T temp = 0;
				if (!WriteProcessMemory(pi.hProcess, LPVOID(breakpointAddress), &breakpointByte, 1, &temp))
				{
					printf("failed to restore breakpoint %p\n", breakpointAddress);
				}

				// unset trap flag
				auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
				if (hThread)
				{
					CONTEXT context;
					context.ContextFlags = CONTEXT_CONTROL;
					GetThreadContext(hThread, &context);
					printf("Rip: %p, Eflags: %x\n", context.Rip, context.EFlags);
					context.EFlags &= ~0x100;
					if (!SetThreadContext(hThread, &context))
					{
						puts("SetThreadContext failed");
					}
					CloseHandle(hThread);
				}
				else
				{
					puts("OpenThread failed");
					continueDebugging = false;
				}
				continueStatus = DBG_CONTINUE;
			}
		}
		break;

		case CREATE_THREAD_DEBUG_EVENT:
		{
		}
		break;

		case CREATE_PROCESS_DEBUG_EVENT:
		{
			const auto& process = debugEvent.u.CreateProcessInfo;
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

				auto setBreakpoint = [&](ULONG_PTR address)
				{
					unsigned char originalByte = 0;
					SIZE_T temp = 0;
					ReadProcessMemory(pi.hProcess, LPVOID(address), &originalByte, 1, &temp);
					unsigned char breakpointByte = 0xCC;
					WriteProcessMemory(pi.hProcess, LPVOID(address), &breakpointByte, 1, &temp);
					breakpoints.emplace(address, originalByte);
					printf("Set breakpoint at %p\n", address);
				};

				setBreakpoint(ULONG_PTR(process.lpStartAddress));
				setBreakpoint(raceFunction);
			}
		}
		break;

		case EXIT_THREAD_DEBUG_EVENT:
		{
		}
		break;

		case EXIT_PROCESS_DEBUG_EVENT:
		{
			continueDebugging = false;
		}
		break;

		case LOAD_DLL_DEBUG_EVENT:
		{
		}
		break;

		case UNLOAD_DLL_DEBUG_EVENT:
		{
		}
		break;

		case OUTPUT_DEBUG_STRING_EVENT:
		{
		}
		break;

		case RIP_EVENT:
		{

		}
		break;
		}

		if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus))
		{
			puts("ContinueDebugEvent failed");
			break;
		}
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return exitCode;
}
