
#include <iostream>

#include "pch.h"

#include "src/emulator.hpp"
#include "src/debugger.hpp"
#include "src/globals.hpp"
#include "src/paging.hpp"
#include "src/utils.hpp"
#include "src/hooks.hpp"

void WINAPI WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS ExtensionApis,
    USHORT MajorVersion, 
    USHORT MinorVersion) {
    
    if (!g_Debugger.Init()) {
        std::println("Failed to initialize debugger instance.\n");
        return;
    }

    if (!g_Hooks.Init()) {
        std::println("Failed to initialize hooks.\n");
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

DECLARE_API(shadow) {
    if (!g_Hooks.Enable()) {
        std::println("[-] Failed to initialize shadow mode.");
        return;
    }

    std::println("[*] Debugger commands are now partially under plugin's control.");

    //
    // Prepare emulator cpu state for further operations.
    //
    CpuState_t CurrentState; // TODO: Fetch the current CPU state.
    LoadCpuStateFromJSON(CurrentState, R"(D:\snapshot_test\state.26100.1.amd64fre.ge_release.240331-1435.20250727_2125\regs.json)");
    g_Emulator.Initialize(CurrentState);

    InShadowState = true;
}

DECLARE_API(unshadow) {
    if (!g_Hooks.Restore()) {
        std::println("[-] Failed to restore from shadow state.");
        return;
    }

    std::println("[*] Returning to original debugger state");
    
    //
    // Reset emulator's state
    //
    g_Emulator.Reset();

    //
    // Flush memory display cache to
    // resync the debugger with the actual ram
    //
    g_Hooks.FlushDbsSplayTreeCache();
    
    InShadowState = false;
}


/*DECLARE_API(saveframe) {
    std::istringstream Stream(args);
    std::uint32_t Index;
    std::uint64_t End;

    //DEBUG

    if (!(Stream >> std::hex >> Index >> End)) {
        std::println("Usuage: !saveframe <index> <end>");
        return;
    }

    std::print("Saving frame... ");

    CpuState_t CurrentCpuState;
    //DEBUG
    LoadCpuStateFromJSON(CurrentCpuState, R"(C:\Users\seant\Downloads\snapshot-test\state.26100.1.amd64fre.ge_release.240331-1435.20250726_1218\regs.json)");
    // g_Debugger.LoadCpuState(CurrentCpuState);

    g_Emulator.Initialize(CurrentCpuState);
    g_Emulator.Run(End);

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

    //
    // TODO: Currently this will only set the state to previous emulation session,
    // if we want to add a jump-to-demand time frame design we need to change the code here.
    //

    // std::println("[*] Restoring dirtied pages...");

    g_Emulator.RestoreDirtiedPage();

    // std::println("[*] Restoring CPU state...");

    g_Debugger.LoadCpuState(g_TimeFrames.at(Index));
}*/