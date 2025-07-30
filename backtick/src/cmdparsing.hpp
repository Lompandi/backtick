#pragma once

#include <string>
#include <vector>

void ExecuteHook(const std::string& Command);

struct GCommandParams {
    bool useHardwareBreakpoint = false;
    bool hasStartAddress = false;
    std::uint64_t startAddress = 0;
    std::vector<std::uint64_t> breakAddresses;
    std::string breakCommands;
};

GCommandParams ParseGCommand(const std::string& command);

std::uint64_t ParseAddress(const std::string& addrStr);