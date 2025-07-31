
#include <windows.h>

#include <set>
#include <detours.h>
#include <fmt/format.h>

#include "hooks.hpp"
#include "globals.hpp"
#include "emulator.hpp"
#include "cmdparsing.hpp"
#include <iostream>

Hooks g_Hooks;

constexpr std::uint64_t Amd64MachineInfoVtableOffset   = 0x633D60;
constexpr std::uint64_t ConnLiveKernelTargetInfoOffset = 0x64E528;
constexpr std::uint64_t DbsSplayTreeCacheVtableOffset  = 0x65FDC8;

constexpr std::uint64_t SetExecStepTraceOffset       = 0x4BF240;
constexpr std::uint64_t SetExecGoOffset              = 0x26337C;
constexpr std::uint64_t SetExecutionStatusOffset     = 0x10AFE0;
constexpr std::uint64_t KdContinueOffset             = 0x198E6C;

constexpr std::uint64_t WaitStateChangeOffset        = 0x1A118C;

constexpr std::uint64_t DbsSplayTreeCacheFlushOffset = 0x487D18;

// LiveKernelTargetInfoCached::ReadVirtual
constexpr std::uint64_t ReadVirtualOffset = 0x1171E0;
using ReadVirtualOffset_t = HRESULT(__fastcall*)(void*, void*, uint64_t, void*, uint32_t, uint32_t*);
static ReadVirtualOffset_t OriginalReadVirtual = nullptr;

constexpr std::uint64_t GetRegValOffset              = 0xA1CC0;
using GetRegisterVal_t = HRESULT(__fastcall*)(void*, ULONG, REGVAL*);
static GetRegisterVal_t OriginalGetRegisterVal = nullptr;

constexpr std::uint64_t WriteVirtualOffset = 0x119EC0;
using WriteVirtual_t = HRESULT(__fastcall*)(void*, void*, uint64_t, void*, uint32_t, uint32_t*);
static WriteVirtual_t OriginalWriteVirtual = nullptr;

struct _ADDR {
    std::uint64_t Type;
    std::uint64_t Value1;
    std::uint64_t Value2;
    std::uint64_t Unk1;
};

constexpr std::uint64_t GetPcOffset = 0xA0AD0;
using GetPc_t = HRESULT(__fastcall*)(std::uint64_t, _ADDR*);
static GetPc_t OriginalGetPcVal = nullptr;

constexpr std::uint64_t ExecuteCommandOffset = 0x100F10;
using ExecuteCommand_t = HRESULT(__fastcall*)(struct DebugClient*, const unsigned __int16*, signed int, int);
static ExecuteCommand_t OriginalExecuteCommand = nullptr;

void* DbsSplayTreeCacheFlushAddress = nullptr;

// 48 e9 ff ff ?? ?? ff ff 

bool SkipEventWait = false;

uint64_t DbgEngBase = 0;

constexpr bool HooksDebugging = false;

std::set<std::uint64_t> g_DbsSplayTreeCacheInstanceAddresses;



//
// Block debugger to send packet to target machine when single-stepping
// TODO:
//   - DisableNetworkSendingFunction
// -> hook DbgKdTransport::WaitForPacket (return 0x80b00005 in normal senario)
// for early return at dbgeng!DbgKdTransport::WriteDataPacket+0x2c5 (0x18011DE28) ?
//

template <typename... Args_t>
void HooksDbg(const char* Format, const Args_t &...args) {
    if constexpr (HooksDebugging) {
        fmt::print("hooks: ");
        fmt::print(fmt::runtime(Format), args...);
        fmt::print("\n");
    }
}

static HRESULT SetRegisterValHook(uint64_t pThis, ULONG Index, REGVAL* pRegVal) {
    HooksDbg("[*] Setting register {:#x} to {}", Index, pRegVal->ToString());

    if (!g_Emulator.SetReg((Registers_t)Index, pRegVal)) {
        return E_INVALIDARG;
    }

    return S_OK;
}

static HRESULT GetRegisterValHook(void* pThis, ULONG Index, REGVAL* pRegVal) {
    HooksDbg("[*] Reading register {:#x}", Index);

    if (g_Emulator.GetReg((Registers_t)Index, pRegVal)) {
        return S_OK;
    }

    return OriginalGetRegisterVal(
        pThis, Index, pRegVal
    );
}

static HRESULT ReadVirtualHook(void* pThis, void* Process, uint64_t ReadAddress, void* Buffer, uint32_t Size, uint32_t* BytesRead) {
    HooksDbg("[*] {:#x} Reading {} bytes from {:#x}", (uintptr_t)pThis, Size, ReadAddress);

    //
    // Check whether it is mapped, if not, foward the execution flow to original function
    //

    if (!g_Emulator.IsGvaMapped(ReadAddress)) {
        return OriginalReadVirtual(pThis, Process, ReadAddress, Buffer, Size, BytesRead);
    }

    if (!g_Emulator.VirtRead(ReadAddress, (uint8_t*)Buffer, Size)) {
        return S_FALSE;
    }

    *BytesRead = Size;
    return S_OK;
}

// eb address value -> data -> cache
// db address <-> cache < network > target
// shadow
// eb address value -> cache -> emulator
//unshadow
//db address ->

static HRESULT WriteVirtualHook(void* pThis, void* Process, uint64_t WriteAddress, void* Buffer, uint32_t Size, uint32_t* BytesWritten) {
    HooksDbg("[*] Writing {} bytes to {:#x}", Size, WriteAddress);

    //TODO: Idk if the page is not loaded probably bring it up before writing to it
    if (!g_Emulator.VirtWrite(WriteAddress, (const uint8_t*)Buffer, Size)) {
        return S_FALSE;
    }

    *BytesWritten = Size;
    return S_OK;
}

static HRESULT SetExecStepTraceHook(std::uint64_t pThis, 
    std::uint64_t pAddr, std::uint64_t StepTracePassCheck, 
    std::uint64_t a1, const std::uint16_t* a2, std::uint64_t pThreadInfo, 
    int a3, std::uint64_t InternalCmdState) {


    return S_OK;
}

static HRESULT GetPcHook(std::uint64_t pThis, _ADDR* pAddr) { 
    pAddr->Type = 0x0000000000100028;
    pAddr->Value1 = g_Emulator.Rip();
    pAddr->Value2 = g_Emulator.Rip();
    return S_OK;
}

static HRESULT SetPcHook(std::uint64_t pThis, _ADDR* pAddr) {
    g_Emulator.Rip(pAddr->Value1);
    return S_OK;
}

static HRESULT LiveKernelTargetInfoCached__ReadVirtualHook(void* pThis,
    void* ProcessInfo, std::uint64_t Address, void* Buffer, ULONG Size, ULONG* OutSize) {

    if (ProcessInfo != nullptr) {

        std::uint64_t DbsSplayTreeCacheAddress
            = (uint64_t)((char*)ProcessInfo + 0x4f8);

        if (!g_DbsSplayTreeCacheInstanceAddresses.contains(DbsSplayTreeCacheAddress)) {
            g_DbsSplayTreeCacheInstanceAddresses.insert(DbsSplayTreeCacheAddress);
            std::println("DbsSplayTreeCache: {:#x}", DbsSplayTreeCacheAddress);
        }
    }

    using OriginalFunc = HRESULT(__fastcall*)(void*, void*, std::uint64_t, void*, ULONG, ULONG*);
    return g_Hooks.CallOriginalTyped<OriginalFunc>(&LiveKernelTargetInfoCached__ReadVirtualHook,
        pThis, ProcessInfo, Address, Buffer, Size, OutSize);
}

static HRESULT LiveKernelTargetInfoCached__WriteVirtualHook(void* pThis,
    void* ProcessInfo, std::uint64_t Address, void* Buffer, ULONG Size, ULONG* OutSize) {

    if (ProcessInfo != nullptr) {

        std::uint64_t DbsSplayTreeCacheAddress
            = (uint64_t)((char*)ProcessInfo + 0x4f8);

        if (!g_DbsSplayTreeCacheInstanceAddresses.contains(DbsSplayTreeCacheAddress)) {
            g_DbsSplayTreeCacheInstanceAddresses.insert(DbsSplayTreeCacheAddress);
            std::println("DbsSplayTreeCache: {:#x}", DbsSplayTreeCacheAddress);
        }
    }

    using OriginalFunc = HRESULT(__fastcall*)(void*, void*, std::uint64_t, void*, ULONG, ULONG*);
    return g_Hooks.CallOriginalTyped<OriginalFunc>(&LiveKernelTargetInfoCached__WriteVirtualHook,
        pThis, ProcessInfo, Address, Buffer, Size, OutSize);
}

static HRESULT ExecuteCommandHook(struct DebugClient* Client,
    const unsigned __int16* Command, signed int a2, int a1) {

    std::u16string WCommandString;
    WCommandString.assign(reinterpret_cast<const char16_t*>(Command));

    if (ExecuteHook(WCommandString)) {
        return S_OK;
    }

    return OriginalExecuteCommand(Client, Command, a2, a1);
}

void Hooks::FlushDbsSplayTreeCache() {
    //
    // Haven't get the memory display instance yet
    //
    if (g_DbsSplayTreeCacheInstanceAddresses.empty()) {
        return;
    }

    for (const auto& Instance : g_DbsSplayTreeCacheInstanceAddresses) {
        using Func_t = void(__fastcall*)(void*);
        return reinterpret_cast<Func_t>(DbsSplayTreeCacheFlushAddress)((void*)Instance);
    }
}

void Hooks::RegisterVtableHook(void** Vtable, size_t Index, void* HookFunc) {
    RegisteredHooks_.push_back(std::tie(Vtable, Index, HookFunc));
}

bool Hooks::Enable() {
    for (const auto& [Vtable, Index, HookFunc] : RegisteredHooks_) {
        HookVtable(Vtable, Index, HookFunc);
    }

    DbgEngBase = (std::uint64_t)GetModuleHandleA("dbgeng.dll");

    OriginalGetPcVal = reinterpret_cast<GetPc_t>(AddDetour(
        (void*)(DbgEngBase + GetPcOffset), (void*)GetPcHook
    ));

    OriginalGetRegisterVal = reinterpret_cast<GetRegisterVal_t>(AddDetour(
        (void*)(DbgEngBase + GetRegValOffset), (void*)GetRegisterValHook
    ));

    OriginalExecuteCommand = reinterpret_cast<ExecuteCommand_t>(AddDetour(
        (void*)(DbgEngBase + ExecuteCommandOffset), (void*)ExecuteCommandHook
    ));

    OriginalReadVirtual = reinterpret_cast<ReadVirtualOffset_t>(AddDetour(
        (void*)(DbgEngBase + ReadVirtualOffset), (void*)ReadVirtualHook
    ));

    OriginalWriteVirtual = reinterpret_cast<WriteVirtual_t>(AddDetour(
        (void*)(DbgEngBase + WriteVirtualOffset), (void*)WriteVirtualHook
    ));

    return true;
}

bool Hooks::RestorePatchedBytes() {
    for (const auto& [address, restoreBytes] : PatchedBytes_) {
        DWORD oldProtect;
        size_t length = restoreBytes.size();

        if (VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(address, restoreBytes.data(), length);
            VirtualProtect(address, length, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), address, length);
        }
    }

    PatchedBytes_.clear();
    return true;
}


bool Hooks::Restore() {
    //
    // Remove all VTable hooks
    //
    for (auto& [targetAddress, originalFunc] : Originals_) {
        DWORD oldProtect;
        VirtualProtect(targetAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        *targetAddress = originalFunc;
        VirtualProtect(targetAddress, sizeof(void*), oldProtect, &oldProtect);
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OriginalExecuteCommand, ExecuteCommandHook);
    DetourDetach(&(PVOID&)OriginalGetRegisterVal, GetRegisterValHook);
    DetourDetach(&(PVOID&)OriginalGetPcVal,       GetPcHook);
    DetourDetach(&(PVOID&)OriginalReadVirtual,    ReadVirtualHook);
    DetourDetach(&(PVOID&)OriginalWriteVirtual,   WriteVirtualHook);
    DetourTransactionCommit();

    DetouredFunctions_.clear();

    return true;
}

bool Hooks::Init() {
	std::uintptr_t DbgEngBase = (std::uint64_t)GetModuleHandleA("dbgeng.dll");

	// std::println("[*] dbgeng.dll: {:#x}", DbgEngBase);

    DbsSplayTreeCacheFlushAddress = (void*)(DbgEngBase + DbsSplayTreeCacheFlushOffset);

    // SetReg Hook
    RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x44, &SetRegisterValHook);

    // GetReg Hook
    // RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x42, &GetRegisterValHook);

    // GetPC Hook
    // RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x46, &GetPcHook);

    // SetPC Hook
    RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x47, &SetPcHook);

    // ConnLiveKernelTargetInfo::DoWriteVirtualMemory
    // RegisterVtableHook((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0xC3, &DoWriteVirtualMemoryHook);


    RegisterVtableHook((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0x1E, &LiveKernelTargetInfoCached__ReadVirtualHook);

    // RegisterVtableHook((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0x21, &LiveKernelTargetInfoCached__WriteVirtualHook);



	return true;
}

void* Hooks::AddDetour(void* targetFunc, void* detourFunc) {
    void* original = targetFunc;

    if (DetourTransactionBegin() != NO_ERROR ||
        DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
        DetourAttach(&original, detourFunc) != NO_ERROR ||
        DetourTransactionCommit() != NO_ERROR) {
        std::println("Detour attach failed for {}", targetFunc);
        return nullptr;
    }

    DetouredFunctions_[targetFunc] = original;
    HookedToOriginal_[detourFunc] = targetFunc;
    return original;
}

void Hooks::HookVtable(void** vtable, size_t index, void* hookFunc) {
    void** targetAddress = &vtable[index];

    if (!IsBadReadPtr(targetAddress, sizeof(void*))) {
        if (Originals_.count(targetAddress) == 0) {
            Originals_[targetAddress] = *targetAddress;
            //
            // TODO: Is there any other way we can implement this?
            //
            HookedToOriginal_[hookFunc] = *targetAddress;
        }

        DWORD oldProtect;
        VirtualProtect(targetAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        *targetAddress = hookFunc;
        VirtualProtect(targetAddress, sizeof(void*), oldProtect, &oldProtect);
    }
    else {
        HooksDbg("[!] Vtable index {} is not readable at address {:p}", index, (void*)targetAddress);
    }
}
