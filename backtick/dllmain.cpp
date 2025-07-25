
#include <iostream>
#include <fmt/format.h>

#include "pch.h"

#include "src/emulator.hpp"
#include "src/debugger.hpp"
#include "src/globals.hpp"
#include "src/paging.hpp"
#include "src/utils.hpp"

void WINAPI WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS ExtensionApis,
    USHORT MajorVersion, 
    USHORT MinorVersion) {
    
    if (!g_Debugger.Init()) {
        std::println("Failed to initialize debugger instance.\n");
        return;
    }
}

LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void) {
    return &g_ExtApiVersion;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DECLARE_API(saveframe) {
    std::istringstream Stream(args);
    std::uint32_t Index;
    std::uint64_t End;

    if (!(Stream >> std::hex >> Index >> End)) {
        std::println("Usuage: !saveframe <index> <end>");
        return;
    }

    std::print("Saving frame... \n");

    CpuState_t CurrentCpuState;
    //DEBUG
    LoadCpuStateFromJSON(CurrentCpuState, R"(D:\baddriversnapshot\state.26100.1.amd64fre.ge_release.240331-1435.20250724_2240\regs.json)");

    Emulator Emu;
    Emu.Initialize(CurrentCpuState);
    Emu.Run(End);

    g_TimeFrames[Index] = CurrentCpuState;

    std::print("{}\n", Index);
}

DECLARE_API(frame) {
    std::istringstream Stream(args);
    std::uint32_t Index;

    if (!(Stream >> std::hex >> Index)) {
        std::println("Usuage: !frame <index>");
        return;
    }

    if (!g_TimeFrames.contains(Index)) {
        std::println("Specified time frame doesn't exist");
        return;
    }

    if (!g_Emulator) {
        std::println("No active timeframe instance");
        return;
    }

    //
    // TODO: Currently this will only set the state to previous emulation session,
    // if we want to add a jump-to-demand time frame design we need to change the code here.
    //
    for (const auto& DirtiedPage : g_Emulator->GetDirtedPage()) {
        g_Debugger.WritePhysicalMemory(DirtiedPage.first, DirtiedPage.second.get(), Page::Size);
        // DEBUG
        std::println("[*] Restoring page @ {:#010x}", DirtiedPage.first);
    }

    g_Debugger.LoadCpuState(g_TimeFrames.at(Index));
}