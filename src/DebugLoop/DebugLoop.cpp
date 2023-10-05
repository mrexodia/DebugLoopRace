#include <map>
#include <vector>
#include <cassert>
#include <utility>
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
	std::map<DWORD, HANDLE> threads;
	ULONG_PTR raceFunction = 0, raceCounter = 0;

	bool suspendRequested = false;
	DWORD threadSteppingId = 0;
	std::vector<std::pair<DWORD, HANDLE>> suspendedThreads;
	auto synchronizedSingleStep = [&](DWORD threadId)
	{
		auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
		if (hThread)
		{
			CONTEXT context;
			context.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(hThread, &context);
			context.EFlags |= 0x100;
			//context.Rip = breakpointItr->first;
			SetThreadContext(hThread, &context);
			CloseHandle(hThread);

			// Indicate that this thread is stepping
			threadSteppingId = threadId;

			// Request all other threads to be suspended
			suspendRequested = true;

			return true;
		}
		else
		{
			return false;
		}
	};
	int exitCode = EXIT_FAILURE;
	unsigned int breakpointHitCounter = 0;
	unsigned int expectedHitCounter = 0;
	ULONG_PTR breakpointAddress = 0;
	bool systemBreakpoint = false;
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
			if (threadSteppingId != 0 && debugEvent.dwThreadId != threadSteppingId)
			{
				// Reply later if we are currently stepping
				continueStatus = DBG_REPLY_LATER;
			}
			else if (exception.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				breakpointAddress = (ULONG_PTR)exception.ExceptionAddress;
				auto breakpointItr = breakpoints.find(breakpointAddress);
				if (breakpointItr != breakpoints.end())
				{
					printf("Hit breakpoint %p\n", breakpointAddress);
					breakpointHitCounter++;
					// restore original byte
					SIZE_T temp = 0;
					if (!WriteProcessMemory(pi.hProcess, LPVOID(breakpointAddress), &breakpointItr->second, 1, &temp))
					{
						puts("failed to restore original byte");
					}
					// set trap flag
					if (!synchronizedSingleStep(debugEvent.dwThreadId))
					{
						puts("Error: synchronizedSingleStep");
						continueDebugging = false;
					}
					continueStatus = DBG_CONTINUE;
				}
				else if (!systemBreakpoint)
				{
					puts("system breakpoint!");
					systemBreakpoint = true;
				}
				else
				{
					auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
					if (!hThread)
						__debugbreak();
					CONTEXT Context;
					Context.ContextFlags = CONTEXT_CONTROL;
					if (!GetThreadContext(hThread, &Context))
						__debugbreak();
					printf("Hit int3 %p (RIP: %p, FirstChance: %u)\n", breakpointAddress, Context.Rip, debugEvent.u.Exception.dwFirstChance);
					continueStatus = DBG_CONTINUE;
					// single step
					Context.EFlags |= 0x100;
					SetThreadContext(hThread, &Context);
					CloseHandle(hThread);
				}
			}
			else if (exception.ExceptionCode == EXCEPTION_SINGLE_STEP) // threadSteppingId == debugEvent.dwThreadId ?
			{
				if (threadSteppingId != 0)
				{
					// Confirm the single step event is for the thread we expect
					assert(threadSteppingId == debugEvent.dwThreadId);

					// Resume the other threads
					for (const auto& itr : suspendedThreads)
					{
						ResumeThread(itr.second);
					}
					suspendedThreads.clear();
					threadSteppingId = 0;

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
				else
				{
					puts("Allow single step!");
					continueStatus = DBG_CONTINUE;
				}
			}
			else
			{
				printf("Exception: %08X, FirstChance: %u\n", exception.ExceptionCode, debugEvent.u.Exception.dwFirstChance);
			}
		}
		break;

		case CREATE_THREAD_DEBUG_EVENT:
		{
			auto threadId = debugEvent.dwThreadId;
			assert(threads.count(threadId) == 0);
			auto hThread = OpenThread(THREAD_ALL_ACCESS, false, threadId);
			if (hThread == nullptr)
			{
				// TODO: THREAD_ALL_ACCESS?
				DuplicateHandle(GetCurrentProcess(), debugEvent.u.CreateThread.hThread, GetCurrentProcess(), &hThread, 0, FALSE, DUPLICATE_SAME_ACCESS);
			}
			threads.emplace(threadId, hThread);
		}
		break;

		case CREATE_PROCESS_DEBUG_EVENT:
		{
			// manage threads
			auto threadId = debugEvent.dwThreadId;
			assert(threads.count(threadId) == 0);
			auto hThread = OpenThread(THREAD_ALL_ACCESS, false, threadId);
			assert(hThread != nullptr);
			threads.emplace(threadId, hThread);

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

				//setBreakpoint(ULONG_PTR(process.lpStartAddress)); // entry breakpoint (for testing)
				if(raceFunction)
					setBreakpoint(raceFunction);
			}
		}
		break;

		case EXIT_THREAD_DEBUG_EVENT:
		{
			auto threadId = debugEvent.dwThreadId;

			// The thread that was stepping terminated, resume the threads we suspended
			if (threadSteppingId == threadId)
			{
				for (const auto& itr : suspendedThreads)
				{
					ResumeThread(itr.second);
				}
				suspendedThreads.clear();
				threadSteppingId = 0;
			}
			assert(threads.count(threadId) != 0);
			auto hThread = threads.at(threadId);
			CloseHandle(hThread);
			threads.erase(threadId);
		}
		break;

		case EXIT_PROCESS_DEBUG_EVENT:
		{
			SIZE_T temp = 0;
			ReadProcessMemory(pi.hProcess, (LPVOID)raceCounter, &expectedHitCounter, sizeof(expectedHitCounter), &temp);
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
			assert(false);
		}
		break;
		}

		if (suspendRequested)
		{
			auto threadId = debugEvent.dwThreadId;

			// Make sure the request is for the current thread
			assert(threadSteppingId == threadId);

			// Suspend all other threads to handle race condition
			assert(suspendedThreads.empty());
			for (const auto& itr : threads)
			{
				if (itr.first != threadId)
				{
					if (SuspendThread(itr.second) != (DWORD)-1)
					{
						suspendedThreads.push_back(itr);
					}
				}
			}

			// The suspend request has been handled
			suspendRequested = false;
		}

		auto statusName = "<unknown>";
		if (continueStatus == DBG_CONTINUE)
			statusName = "DBG_CONTINUE";
		else if (continueStatus == DBG_EXCEPTION_NOT_HANDLED)
			statusName = "DBG_EXCEPTION_NOT_HANDLED";
		else if (continueStatus == DBG_EXCEPTION_HANDLED)
			statusName = "DBG_EXCEPTION_HANDLED";
		else if (continueStatus == DBG_REPLY_LATER)
			statusName = "DBG_REPLY_LATER";
		printf("ContinueDebugEvent(%u, %u, %s)\n", debugEvent.dwProcessId, debugEvent.dwThreadId, statusName);
		if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus))
		{
			puts("ContinueDebugEvent failed");
			break;
		}
	}

	// Clean up threads
	for (const auto& itr : threads)
	{
		CloseHandle(itr.second);
	}
	threads.clear();

	// Close process handles
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	printf("breakpointHitCounter: %d == %d (%s)\n", breakpointHitCounter, expectedHitCounter, breakpointHitCounter == expectedHitCounter ? "GOOD" : "BAD");

	system("pause");

	return exitCode;
}
