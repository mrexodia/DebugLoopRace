// Headless TitanEngine multi-thread breakpoint/step race harness.
//
// Drives TitanEngine's DebugLoop directly against a racy debuggee (RaceFunction hit by
// 5 worker threads, plus ControlFunction/Control2Function control points) and asserts
// the engine keeps its per-thread breakpoint and single-step state straight.
//
// Modes (argv[2]):
//   hijack     - Suspend the main thread at ControlFunction and arm a single-step on
//                it. Its step stays pending while the workers keep hitting RaceFunction;
//                on a buggy engine a worker's automatic breakpoint step-over consumes
//                the global step state and fires the step callback on the WRONG thread
//                (and corrupts the step-over accounting).
//   multistep  - Arm single-steps on TWO suspended threads (main + a stepper) at once.
//                A single global stepping slot can only hold one, so the second step is
//                silently dropped; per-thread state fires both.
//   hwhijack   - hijack, but RaceFunction has a hardware (DR0) execute breakpoint.
//   memhijack  - hijack, but RaceFunction has a memory (page-guard) execute breakpoint.
//                RaceFunction lives in its own code section so the guard covers only it.
//   swstress   - No stepping; just hammer a software breakpoint from all threads.
//   hwstress   - No stepping; hammer a hardware breakpoint from all threads.
//   memstress  - No stepping; hammer a memory breakpoint from all threads.
//   hwexit     - Hammer a hardware breakpoint and, from the hit callback, terminate the
//                hitting thread so it exits mid-step-over. On a buggy engine the orphaned
//                reset state corrupts the next thread's event into a stray single-step
//                that crashes the debuggee. Deterministic regression test for the
//                hardware-breakpoint reset race.
//
// PASS = every armed step's callback fires exactly once on its own thread, no step
// callback fires on a thread it was not armed on, the debuggee exits cleanly (a crash
// from a stray single-step yields a non-zero exit code), and for software breakpoints
// bp hits == RaceCounter.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include "TitanEngine.h"

static PROCESS_INFORMATION pi;
static ULONG_PTR raceFunction = 0, race2Function = 0, controlFunction = 0, control2Function = 0;
static ULONG_PTR raceCounter = 0;
static const char* mode = "hijack";

// hw2exit: a second hardware breakpoint (DR1) on Race2Function, to check that it keeps
// firing after the DR0 breakpoint runs through the thread-exit reset-recovery path.
static std::atomic<unsigned> race2Hits{0};
static std::atomic<unsigned> race2AtLastTerminate{0};

static std::atomic<unsigned> bpHits{0};
static std::atomic<unsigned> stepCbTotal{0};
static std::atomic<unsigned> stepCbWrongThread{0};
static std::atomic<unsigned> raceHitsSinceArmed{0};
static std::atomic<int> armedCount{0};
static unsigned expectedRace = 0;
static DWORD exitCode = 0xFFFFFFFF; // debuggee exit code (a stray-single-step crash -> non-zero)

// up to 2 armed steps: (tid, whether its callback fired on the right thread)
static std::atomic<DWORD> armedTid[2] = {};
static std::atomic<unsigned> firedForArmed[2] = {};
static std::atomic<HANDLE> suspended[2] = {};

static DWORD curTid() { return ((DEBUG_EVENT*)GetDebugData())->dwThreadId; }
static bool isStress() { return strstr(mode, "stress") != nullptr; }
static bool isExit() { return strstr(mode, "exit") != nullptr; } // hwexit / hw2exit
// Modes that arm a single-step at the control breakpoint (the step-hijack tests). The
// stress and *exit modes only exercise breakpoint step-over reset, no user stepping.
static bool armsStep() { return !isStress() && !isExit(); }

static void resumeAll()
{
    for (int i = 0; i < 2; i++)
    {
        HANDLE h = suspended[i].exchange(nullptr);
        if (h) { ResumeThread(h); CloseHandle(h); }
    }
}

static void cbStep()
{
    stepCbTotal++;
    DWORD t = curTid();
    bool matched = false;
    for (int i = 0; i < 2; i++)
        if (armedTid[i].load() == t) { firedForArmed[i]++; matched = true; }
    if (!matched)
        stepCbWrongThread++;
}

static void armStepOnCurrentThread(int slot)
{
    DWORD tid = curTid();
    armedTid[slot] = tid;
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (h) { SuspendThread(h); suspended[slot] = h; }
    StepInto(cbStep);
    armedCount++;
    printf("armed step slot %d on tid=%u (suspended)\n", slot, tid);
}

static void cbControlBp()
{
    static std::atomic<bool> once{false};
    if (once.exchange(true)) return;
    if (!armsStep()) return; // stress / hwexit: just hammer the bp, no stepping
    armStepOnCurrentThread(0);
}

static void cbControl2Bp()
{
    static std::atomic<bool> once{false};
    if (once.exchange(true)) return;
    armStepOnCurrentThread(1);
}

static void onRaceHit()
{
    bpHits++;
    int need = (strcmp(mode, "multistep") == 0) ? 2 : 1;
    if (armedCount.load() >= need)
    {
        unsigned n = ++raceHitsSinceArmed;
        if (n == 400)
            resumeAll();
    }
}
static void cbRaceBp() { onRaceHit(); }                 // software bp callback
static void cbRace2Hw(const void*) { race2Hits++; }     // DR1 target (hw2exit)
static void cbRaceHwMem(const void*)                    // hw / memory bp callback
{
    onRaceHit();
    // hwexit / hw2exit: deterministically reproduce a thread exiting while it is in the
    // middle of a breakpoint step-over. We are inside the hit callback (the step-over
    // has been set up but the single-step has not happened yet); terminating this thread
    // now makes its EXIT_THREAD arrive while it is the thread-being-processed, orphaning
    // the reset state on a buggy engine.
    if (isExit())
    {
        unsigned n = bpHits.load();
        if (n == 30 || n == 60 || n == 90)
        {
            if (n == 90) race2AtLastTerminate = race2Hits.load();
            HANDLE h = OpenThread(THREAD_TERMINATE, FALSE, curTid());
            if (h) { TerminateThread(h, 0); CloseHandle(h); }
        }
    }
}

static void cbCreateProcess(CREATE_PROCESS_DEBUG_INFO* info)
{
    wchar_t path[MAX_PATH] = L"";
    GetFinalPathNameByHandleW(info->hFile, path, MAX_PATH, VOLUME_NAME_DOS);
    CloseHandle(info->hFile);
    auto base = (ULONG_PTR)info->lpBaseOfImage;
    auto hLib = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (hLib)
    {
        auto rel = [&](const char* n) -> ULONG_PTR {
            auto a = (ULONG_PTR)GetProcAddress(hLib, n);
            return a ? a - (ULONG_PTR)hLib + base : 0;
        };
        raceFunction = rel("RaceFunction");
        race2Function = rel("Race2Function");
        controlFunction = rel("ControlFunction");
        control2Function = rel("Control2Function");
        raceCounter = rel("RaceCounter");
        FreeLibrary(hLib);
    }
    printf("mode=%s Race=%p Control=%p Control2=%p\n", mode, (void*)raceFunction, (void*)controlFunction, (void*)control2Function);
    // Singleshoot control bps: no step-over reset / no synchronizedStep, so suspending
    // the stepped thread in the callback cannot deadlock the loop.
    SetBPX(controlFunction, UE_SINGLESHOOT, cbControlBp);
    if (strcmp(mode, "multistep") == 0)
        SetBPX(control2Function, UE_SINGLESHOOT, cbControl2Bp);
    // The worker-hit breakpoint on RaceFunction. Its automatic step-over is the path
    // that (on a buggy engine) hijacks the pending step. Exercise all bp types so the
    // fix is validated for software, hardware and memory breakpoints.
    if (strstr(mode, "hw"))
        SetHardwareBreakPoint(raceFunction, UE_DR0, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, cbRaceHwMem);
    else if (strstr(mode, "mem"))
        SetMemoryBPXEx(raceFunction, 1, UE_MEMORY_EXECUTE, true, cbRaceHwMem);
    else
        SetBPX(raceFunction, UE_BREAKPOINT, cbRaceBp);
    // hw2exit / hw2stress: a SECOND hardware breakpoint (DR1) on Race2Function, hit by its
    // own thread. In hw2exit the DR0 breakpoint goes through the thread-exit reset-recovery
    // path and DR1 must keep firing afterward; hw2stress runs the same two breakpoints with
    // no thread exit, to tell whether a DR1 loss comes from the recovery or is a plain
    // two-hardware-breakpoint bug.
    if (strstr(mode, "hw2"))
        SetHardwareBreakPoint(race2Function, UE_DR1, UE_HARDWARE_EXECUTE, UE_HARDWARE_SIZE_1, cbRace2Hw);
}

static void cbExitProcess(EXIT_PROCESS_DEBUG_INFO* info)
{
    SIZE_T n = 0;
    if (raceCounter) ReadProcessMemory(pi.hProcess, (LPVOID)raceCounter, &expectedRace, sizeof(expectedRace), &n);
    if (info) exitCode = info->dwExitCode;
    resumeAll();
}

int wmain(int argc, wchar_t** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) { puts("Usage: TestStepRace StepRaceMe.exe [mode]"); return 2; }
    static char modebuf[32] = "hijack";
    if (argc >= 3) { wcstombs(modebuf, argv[2], sizeof(modebuf)); mode = modebuf; }

    auto p = InitDebugW(argv[1], nullptr, nullptr);
    if (!p) { puts("InitDebugW failed"); return 2; }
    pi = *p;
    SetCustomHandler(UE_CH_CREATEPROCESS, (TITANCALLBACKARG)cbCreateProcess);
    SetCustomHandler(UE_CH_EXITPROCESS, (TITANCALLBACKARG)cbExitProcess);
    DebugLoop();

    int need = !armsStep() ? 0 : ((strcmp(mode, "multistep") == 0) ? 2 : 1);
    // Software bps fire exactly once per execution; hw/memory bps use the page-guard /
    // debug-register machinery and are not necessarily 1:1, so the count is only a hard
    // assertion for software breakpoints.
    bool countIsHardAssert = !strstr(mode, "hw") && !strstr(mode, "mem");
    bool bpOk = (bpHits.load() == expectedRace);
    bool stepsOk = (stepCbWrongThread.load() == 0);
    for (int i = 0; i < need; i++)
        if (firedForArmed[i].load() != 1) stepsOk = false;

    // The debuggee must exit cleanly. A stray single-step produced by a corrupted
    // breakpoint/step state gets passed to the debuggee unhandled and terminates it
    // with a non-zero exit code, so this catches the hardware-breakpoint reset crash.
    bool exitOk = (exitCode == 0);

    // hw2exit: after the last DR0 mid-step-over thread exit (and its reset-recovery), the
    // DR1 breakpoint on Race2Function must still be firing. A recovery that rebuilds DR7
    // from the dead thread's (empty) context disables DR1 on the live threads, so its hit
    // count would stop advancing past race2AtLastTerminate.
    bool dr1Survived = true;
    unsigned race2After = 0;
    if (strstr(mode, "hw2"))
    {
        race2After = race2Hits.load() - race2AtLastTerminate.load();
        dr1Survived = (race2After >= 10);
    }

    printf("\n=== mode=%s ===\n", mode);
    printf("RaceFunction bp hits : %u   (expected %u) %s\n", bpHits.load(), expectedRace,
           bpOk ? "OK" : (countIsHardAssert ? "MISMATCH" : "(informational)"));
    for (int i = 0; i < need; i++)
        printf("armed step %d (tid=%u): fired %u time(s) on its own thread\n", i, armedTid[i].load(), firedForArmed[i].load());
    printf("step callbacks       : %u  (WRONG-THREAD: %u)\n", stepCbTotal.load(), stepCbWrongThread.load());
    printf("debuggee exit code   : 0x%08X %s\n", exitCode, exitOk ? "OK" : "CRASH/ABNORMAL");
    if (strstr(mode, "hw2"))
        printf("DR1 hits (Race2Function): %u %s\n", race2After, dr1Survived ? "OK" : "DR1 DISABLED");
    bool pass = stepsOk && exitOk && dr1Survived && (bpOk || !countIsHardAssert);
    printf("RESULT: %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
