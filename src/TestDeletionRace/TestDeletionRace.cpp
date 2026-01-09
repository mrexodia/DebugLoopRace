#include <cstdio>
#include <cstdlib>
#include <TitanEngine.h>

static PROCESS_INFORMATION g_pi;
static ULONG_PTR g_raceFunction = 0;
static ULONG_PTR g_raceCounter = 0;
static bool g_deleted = false;
static unsigned int g_hits = 0;
static unsigned int g_finalCount = 0;

static const unsigned int DELETE_AFTER = 10;

static void cbBreakpoint()
{
    g_hits++;

    if (!g_deleted && g_hits >= DELETE_AFTER)
    {
        printf("hit #%u, deleting breakpoint\n", g_hits);
        DeleteBPX(g_raceFunction);
        g_deleted = true;
    }
}

static void cbCreateProcess(CREATE_PROCESS_DEBUG_INFO* info)
{
    wchar_t path[MAX_PATH] = L"";
    GetFinalPathNameByHandleW(info->hFile, path, MAX_PATH, VOLUME_NAME_DOS);

    auto base = (ULONG_PTR)info->lpBaseOfImage;
    auto hLib = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (hLib)
    {
        auto addr = (ULONG_PTR)GetProcAddress(hLib, "RaceFunction");
        if (addr)
            g_raceFunction = addr - (ULONG_PTR)hLib + base;

        addr = (ULONG_PTR)GetProcAddress(hLib, "RaceCounter");
        if (addr)
            g_raceCounter = addr - (ULONG_PTR)hLib + base;

        FreeLibrary(hLib);
    }

    if (g_raceFunction)
    {
        printf("RaceFunction: %p\n", (void*)g_raceFunction);
        SetBPX(g_raceFunction, UE_BREAKPOINT, cbBreakpoint);
    }
}

static void cbExitProcess(EXIT_PROCESS_DEBUG_INFO* info)
{
    if (g_raceCounter)
    {
        SIZE_T n;
        ReadProcessMemory(g_pi.hProcess, (LPVOID)g_raceCounter, &g_finalCount, sizeof(g_finalCount), &n);
    }

    printf("\nRaceCounter: %u (expected 5001)\n", g_finalCount);
    printf("Exit code:   %lu\n", info->dwExitCode);
    printf("BP hits:     %u\n", g_hits);

    bool ok = (g_finalCount == 5001) && (info->dwExitCode == 0);
    printf("Result:      %s\n", ok ? "PASS" : "FAIL");
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        puts("Usage: TestDeletionRace <DebugMe.exe>");
        return 1;
    }

    auto pi = (PROCESS_INFORMATION*)InitDebugW(argv[1], nullptr, nullptr);
    if (!pi)
    {
        puts("InitDebugW failed");
        return 1;
    }
    g_pi = *pi;

    SetCustomHandler(UE_CH_CREATEPROCESS, (TITANCALLBACKARG)cbCreateProcess);
    SetCustomHandler(UE_CH_EXITPROCESS, (TITANCALLBACKARG)cbExitProcess);

    DebugLoop();

    return (g_finalCount == 5001) ? 0 : 1;
}
