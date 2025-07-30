#include "cmdparsing.hpp"

#include "emulator.hpp"
#include "globals.hpp"

void ExecuteHook(const std::string& Command) {
    std::string cmdStr = Command;

    switch (cmdStr[0]) {
    case 'g': {
        // g[a] [= StartAddress] [BreakAddress ... [; BreakCommands]]
        if (Command == "g" || Command.starts_with("g ") || Command == "ga" ||
            Command.starts_with("ga ")) {
            auto params = ParseGCommand(Command);

            if (params.hasStartAddress) {
                REGVAL* ripVal;
                ripVal->Type = REGVAL_TYPE_I64;
                ripVal->u.I64 = params.startAddress;
                g_Emulator.SetReg(Registers_t::Rip, ripVal);
                std::println("[*] Starting execution from: {:#x}", params.startAddress);
            }

            if (params.breakAddresses.empty()) {
                g_Emulator.Run();
            }
            else {
                for (auto addr : params.breakAddresses) {
                    if (params.useHardwareBreakpoint) {

                    }
                    else {

                    }
                    std::println("[*] Setting breakpoint at: {:#x}", addr);
                    g_Emulator.Run(addr);
                }
            }

            std::println("[*] Execution stopped at: {:#x}", g_Emulator.Rip());
        }
        else if (Command == "gu") {
            REGVAL* rspVal;
            g_Emulator.GetReg(Registers_t::Rsp, rspVal);
            std::uint64_t currentRsp = rspVal->u.I64;

            std::uint64_t returnAddr = g_Emulator.VirtRead8(currentRsp);
            if (returnAddr != 0) {
                g_Emulator.Run(returnAddr);
            }
            else {
                std::println("[!] Could not determine return address");
            }

            std::println("[*] Execution stopped at: {:#x}", g_Emulator.Rip());
        }
        break;
    }
    case 't': {
        break;
    }
    case 'p': {
        break;
    }
    case 'b': {
        break;
    }
    default: {
        std::println("[!] Unknown command!");
    }
    }
}

GCommandParams  ParseGCommand(const std::string& command) {
    GCommandParams params;

    std::string remaining;
    if (command.starts_with("ga ") || command == "ga") {
        params.useHardwareBreakpoint = true;
        remaining = command.length() > 3 ? command.substr(3) : "";
    }
    else if (command.starts_with("g ") || command == "g") {
        remaining = command.length() > 2 ? command.substr(2) : "";
    }
    if (remaining.empty()) {
        return params;
    }

    if (auto pos = remaining.find_first_not_of(" \t"); pos != std::string::npos) {
        remaining = remaining.substr(pos);
    }

    if (auto semicolonPos = remaining.find(';'); semicolonPos != std::string::npos) {
        params.breakCommands = remaining.substr(semicolonPos + 1);
        remaining = remaining.substr(0, semicolonPos);
    }

    // start address (=address)
    if (remaining.starts_with("=")) {
        params.hasStartAddress = true;
        auto spacePos = remaining.find(' ', 1);
        if (spacePos != std::string::npos) {
            params.startAddress = ParseAddress(remaining.substr(1, spacePos - 1));
            remaining = remaining.substr(spacePos + 1);
        }
        else {
            params.startAddress = ParseAddress(remaining.substr(1));
            return params;
        }
    }

    // break addresses
    if (!remaining.empty()) {
        std::string addrStr;
        for (char c : remaining) {
            if (c == ' ' || c == '\t') {
                if (!addrStr.empty()) {
                    params.breakAddresses.push_back(ParseAddress(addrStr));
                    addrStr.clear();
                }
            }
            else {
                addrStr += c;
            }
        }
        if (!addrStr.empty()) {
            params.breakAddresses.push_back(ParseAddress(addrStr));
        }
    }

    return params;
}


std::uint64_t ParseAddress(const std::string& addrStr) {
    std::string trimmed = addrStr;
    if (auto pos = trimmed.find_first_not_of(" \t"); pos != std::string::npos) {
        trimmed = trimmed.substr(pos);
    }
    if (trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
        return std::stoull(trimmed.substr(2), nullptr, 16);
    }

    return std::stoull(trimmed, nullptr, 16);
}