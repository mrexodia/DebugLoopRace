#include <Debugger/Api.hpp>

#include <Windows.h>


enum ContinueStatus
{
    handled_by_debugger,
    dispatch_to_debuggee,
};

struct OsDebuggerInterface
{
    virtual void mem_read(uint64_t address, void* data, size_t size) = 0;
    // reg_read. reg_write, mem_write, memory protection blah


};

struct OsDebugger
{
    ContinueStatus dispatch_exception(ExceptionEvent& event)
    {

    }

    void loop()
    {
        DEBUG_EVENT e;
        WaitForDebugEvent(&e, 0);
        DWORD continue_status = 0;

        switch (e.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
        {
            ExceptionEvent e_api;
            e.u.Exception;
            continue_status = dispatch_exception(e_api);
        }
        break;
        }

        ContinueDebugEvent(0, 1, continue_status);
    }
};

int main()
{
    Debugger dbg;
    dbg.start("DebugMe.exe");
    // example of the callback-based API (for listening)
    //dbg.memory_read_breakpoint(0x1400001010, [](Debugger& dbg, uint64_t address, )
    dbg.breakpoint(0x1400001010, [](Debugger& dbg)
    {
        //callback(dbg, dbg.software_breakpoint());
        //dbg.hardware_event().address
        //dbg.hardware_event().size;
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