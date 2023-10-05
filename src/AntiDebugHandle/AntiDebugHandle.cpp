#include <Windows.h>
#include <cstdio>
#include <cinttypes>

int main()
{
    puts("");

    wchar_t executablePath[MAX_PATH] = L"";
    GetModuleFileNameW(0, executablePath, _countof(executablePath));

    auto hNtdll = CreateFileW(L"C:\\Windows\\system32\\ntdll.dll", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    printf("[AntiDebugHandle] ntdll: 0x%zX (LastError: %u)\n", (uintptr_t)hNtdll, GetLastError());

    auto hExe = CreateFileW(executablePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    printf("[AntiDebugHandle] exe: 0x%zX (LastError: %u)\n", (uintptr_t)hExe, GetLastError());
    
    puts("");
}
