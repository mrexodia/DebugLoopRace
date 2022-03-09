#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <type_traits>

class Awaitable
{
    uint64_t m_id = -1;

    Awaitable() = default;
    explicit Awaitable(uint64_t id) : m_id(id) { }

    Awaitable operator++(int)
    {
        auto cur = *this;
        m_id++;
        return cur;
    }

    friend class Debugger;
};

enum class Register
{
    rax,
    rbx,
    rcx,
    rdx,
    rbp,
    rsp,
    rsi,
    rdi,
    r8,
    r9,
    r10, 
    r11,
    r12,
    r13,
    r14,
    r15,
    eflags,
};

enum class Event
{
    process_create,
    process_exit,
    thread_create,
    thread_exit,
    module_load,
    module_unload,
    exception,
    debug_string,

    system_breakpoint,
    software_breakpoint,
    hardware_breakpoint,
    memory_breakpoint,
    step,
};

class EventData
{

};

class Debugger
{
    Awaitable m_current_awaitable;
    Awaitable m_signalled;

public:
    Debugger();
    ~Debugger();

    using Callback = std::function<void(Debugger&)>;

    void start(const char* process, const char* command_line = nullptr, const char* working_directory = nullptr);

    void breakpoint(uint64_t address, Callback callback);
    Awaitable breakpoint(uint64_t address);

    void hardware_execute(uint64_t address, Callback callback);
    Awaitable hardware_execute(uint64_t address);

    void step(Callback callback);
    Awaitable step();

    uint64_t reg_read(Register reg);
    void reg_write(Register reg, uint64_t value);

    void mem_read(uint64_t address, void* data, size_t size);
    void mem_write(uint64_t address, const void* data, size_t size);

    template<typename T>
    T read(uint64_t address)
    {
        static_assert(std::is_trivially_copyable_v<T> && std::is_default_constructible_v<T>, "");
        T value;
        mem_read(address, &value, sizeof(value));
        return value;
    }

    uint8_t read_byte(uint64_t address)
    {
        return read<uint8_t>(address);
    }

    uint16_t read_word(uint64_t address)
    {
        return read<uint16_t>(address);
    }

    uint32_t read_dword(uint64_t address)
    {
        return read<uint32_t>(address);
    }

    uint64_t read_qword(uint64_t address)
    {
        return read<uint64_t>(address);
    }

    uint64_t read_ptr(uint64_t address)
    {
        return read<uint64_t>(address);
    }

    void await(Awaitable id);
    void loop();

private:
    void loop(Awaitable until_id);
    void signal(Awaitable id);
    bool wait_for_event();
    bool handle_event();
    bool continue_event();
};