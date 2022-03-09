#include <Debugger/Api.hpp>

#include <Windows.h>

enum class AccessOperation
{
    read = 0,
    write = 1,
    execute = 8,
};

enum class HardwareType
{
    access,
    write,
    execute,
};

enum class HardwareSize
{
    size_byte,
    size_word,
    size_dword,
    size_qword,
};

struct DebugEvent
{
    uint32_t process_id = 0;
    uint32_t thread_id = 0;
};

struct ProcessCreateEvent
{
    uint32_t pid = 0;
};

struct ProcessExitEvent
{
    uint32_t pid = 0;
};

struct ThreadCreateEvent
{
    uint32_t tid = 0;
};

struct ThreadExitEvent
{
    uint32_t tid = 0;
};

struct ModuleLoadEvent
{
    uint64_t base = 0;
};

struct ModuleUnloadEvent
{
    uint64_t base = 0;
};

struct ExceptionEvent
{
    bool first_chance = false;
    uint32_t code = 0;
    uint64_t address = 0;
    AccessOperation operation = AccessOperation::read;
    uint64_t access_address = 0;
};

struct DebugStringEvent
{
    std::string message;
};

struct SystemBreakpointEvent
{
};

struct SoftwareBreakpointEvent
{
    uint64_t address = 0;
};

struct HardwareBreakpointEvent
{
    HardwareType type = HardwareType::access;
    HardwareSize size = HardwareSize::size_byte;
};

struct MemoryBreakpointEvent
{
    uint64_t address = 0;
    AccessOperation operation = AccessOperation::read;
};

struct StepEvent
{
};

int main()
{
    Debugger dbg;
    dbg.start("DebugMe.exe");
    // example of the callback-based API (for listening)
    dbg.breakpoint(0x1400001010, [](Debugger& dbg)
    {
        if(dbg.read_byte(dbg.reg_read(Register::rsp) > 3))
        {
            auto rsp = dbg.reg_read(Register::rsp);
            auto return_address = dbg.read<uint64_t>(rsp);
            // example of the await-based API (for scripting)
            dbg.await(dbg.hardware_execute(return_address));
            dbg.await(dbg.step());
            printf("rax: %llx\n", dbg.reg_read(Register::rax));
        }
        else
        {
            dbg.await(dbg.step());
        }
    });
    dbg.loop();
}