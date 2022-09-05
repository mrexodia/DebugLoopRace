#include <Debugger/Api.hpp>

Debugger::Debugger()
{
	m_current_awaitable.m_id = 0;
}

Debugger::~Debugger()
{
}

void Debugger::start(const char* process, const char* command_line, const char* working_directory)
{
}

void Debugger::breakpoint(uint64_t address, Callback callback)
{
}

Awaitable Debugger::breakpoint(uint64_t address)
{
	auto id = m_current_awaitable++;
	breakpoint(address, [id](Debugger& dbg)
	{
		dbg.signal(id);
	});
	return id;
}

void Debugger::hardware_execute(uint64_t address, Callback callback)
{
}

Awaitable Debugger::hardware_execute(uint64_t address)
{
	auto id = m_current_awaitable++;
	hardware_execute(address, [id](Debugger& dbg)
	{
		dbg.signal(id);
	});
	return id;
}

void Debugger::step(Callback callback)
{
}

Awaitable Debugger::step()
{
	auto id = m_current_awaitable++;
	step([id](Debugger& dbg)
	{
		dbg.signal(id);
	});
	return id;
}

uint64_t Debugger::reg_read(Register reg)
{
	return 0;
}

void Debugger::reg_write(Register reg, uint64_t value)
{
}

void Debugger::mem_read(uint64_t address, void* data, size_t size)
{
	memset(data, 0, size);
}

void Debugger::mem_write(uint64_t address, const void* data, size_t size)
{
}

void Debugger::await(Awaitable id)
{
	continue_event();

	while (true)
	{
		if (!wait_for_event())
			throw std::exception();
		if (!dispatch_event())
			throw std::exception();
		if (m_signalled.m_id == id.m_id)
			break;
		if (!continue_event())
			break;
	}
}

void Debugger::signal(Awaitable id)
{
	m_signalled = id;
}

void Debugger::loop(Awaitable until_id)
{
	while (true)
	{
		if (!wait_for_event())
		{
			break;
		}
		if (!dispatch_event())
		{
			break;
		}
		if (!continue_event())
		{
			break;
		}
	}
}

void Debugger::loop()
{
	Awaitable infinite;
	infinite.m_id = -2;
	loop(infinite);
}

bool Debugger::wait_for_event()
{
	return true;
}

bool Debugger::dispatch_event()
{
	// Maybe merge wait_for_event and this function together
	EventData event;
	if (event.type == Event::software_breakpoint)
	{
		auto& e = std::get<SoftwareBreakpointEvent>(event.data);
		m_breakpoints[e.address](*this);
	}
	return true;
}

bool Debugger::continue_event()
{
	return true;
}