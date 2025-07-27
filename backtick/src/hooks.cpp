
#include "hooks.hpp"
#include "globals.hpp"
#include "emulator.hpp"

Hooks g_Hooks;

constexpr std::uint64_t Amd64MachineInfoVtableOffset = 0x633D60;
constexpr std::uint64_t ConnLiveKernelTargetInfoOffset = 0x64E528;

constexpr std::uint64_t SetExecStepTraceOffset = 0x4BF240;
constexpr std::uint64_t SetExecGoOffset = 0x26337C;
constexpr std::uint64_t SetExecutionStatusOffset = 0x10AFE0;

static HRESULT SetRegisterValHook(uint64_t pThis, ULONG Index, REGVAL* pRegVal) {
	std::println("[*] Setting register {:#x} to {}", Index, pRegVal->ToString());

    if (!g_Emulator.SetReg((Registers_t)Index, pRegVal)) {
        return E_INVALIDARG;
    }

    return S_OK;
}

static HRESULT GetRegisterValHook(void* pThis, ULONG Index, REGVAL* pRegVal) {
    std::println("[*] Reading register {:#x}", Index);

    //TODO:
    if (!g_Emulator.GetReg((Registers_t)Index, pRegVal)) {
        using OriginalFunc = HRESULT(__fastcall*)(void* pThis, ULONG Index, REGVAL* pRegVal);
        return g_Hooks.CallOriginalTyped<OriginalFunc>(&GetRegisterValHook, pThis, Index, pRegVal);
    }

    return S_OK;
}

static HRESULT DoReadVirtualMemoryHook(void* pThis, uint64_t ReadAddress, void* Buffer, uint32_t Size, uint32_t* BytesRead) {
    std::println("[*] {:#x} Reading {} bytes from {:#x}", (uintptr_t)pThis, Size, ReadAddress);

    //
    // Check whether it is mapped, if not, foward the execution flow to original function
    //

    //TODO
    if (!g_Emulator.IsGvaMapped(ReadAddress)) {
        using OriginalFunc = HRESULT(__fastcall*)(void* pThis, UINT64 ReadAddress, void* Buffer, uint32_t Size, uint32_t* BytesRead);
        return g_Hooks.CallOriginalTyped<OriginalFunc>(&DoReadVirtualMemoryHook, pThis, ReadAddress, Buffer, Size, BytesRead);
    }

    if (!g_Emulator.VirtRead(ReadAddress, (uint8_t*)Buffer, Size)) {
        return S_FALSE;
    }

    *BytesRead = Size;
    return S_OK;
}

static HRESULT DoWriteVirtualMemoryHook(uint64_t pThis, uint64_t WriteAddress, void* Buffer, uint32_t Size, uint32_t* BytesWritten) {
    std::println("[*] Writing {} bytes to {:#x}", Size, WriteAddress);

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

}

static HRESULT SetExecutionStatusHook(std::uint64_t pDebugClient, ULONG Status) {
    std::println("[*] Setting execution status: {:#x}", Status);
    if (!g_Emulator.RunFromStatus(Status)) {
        return E_INVALIDARG;
    }

    return S_OK;
}

void Hooks::RegisterVtableHook(void** Vtable, size_t Index, void* HookFunc) {
    RegisteredHooks_.push_back(std::tie(Vtable, Index, HookFunc));
}

bool Hooks::Enable() {
    for (const auto& [Vtable, Index, HookFunc] : RegisteredHooks_) {
        HookVtable(Vtable, Index, HookFunc);
    }

    std::uintptr_t DbgEngBase = (std::uint64_t)GetModuleHandleA("dbgeng.dll");

    void* OSetExecutionStatusHook
        = AddJmpHook((void*)(DbgEngBase + SetExecutionStatusOffset), SetExecutionStatusHook);

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

    //
    // Remove all tranpoline instruction
    //
    RestorePatchedBytes();

    Originals_.clear();
    return true;
}

bool Hooks::Init() {
	std::uintptr_t DbgEngBase = (std::uint64_t)GetModuleHandleA("dbgeng.dll");

	// std::println("[*] dbgeng.dll: {:#x}", DbgEngBase);

    // SetReg Hook
    //HookVtable((void**)(DbgEngBase + Amd64MachineInfoVtableOffset), 0x44, &SetRegisterValHook);
    RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x44, &SetRegisterValHook);

    // GetReg Hook
    //HookVtable((void**)(DbgEngBase + Amd64MachineInfoVtableOffset), 0x42, &GetRegisterValHook);
    RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x42, &GetRegisterValHook);

    // ConnLiveKernelTargetInfo::DoResdVirtualMemory Hook
    //HookVtable((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0xC2, &DoReadVirtualMemoryHook);
    RegisterVtableHook((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0xC2, &DoReadVirtualMemoryHook);

    // ConnLiveKernelTargetInfo::DoWriteVirtualMemory
    RegisterVtableHook((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0xC3, &DoWriteVirtualMemoryHook);

	return true;
}

void* Hooks::AddJmpHook(void* target, void* detour) {
    BYTE* src = static_cast<BYTE*>(target);
    BYTE* dst = static_cast<BYTE*>(detour);

    DWORD oldProtect;
    const size_t hookLength = 12; // Length of mov rax + jmp rax

    //
    // Backup original bytes
    //
    std::vector<BYTE> originalBytes(src, src + hookLength);
    PatchedBytes_[target] = originalBytes;

    BYTE* Trampoline = (BYTE*)VirtualAlloc(nullptr, hookLength + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!Trampoline) return nullptr;

    memcpy(Trampoline, src, hookLength);

    uintptr_t jmpBackAddr = (uintptr_t)(src + hookLength);
    Trampoline[hookLength] = 0x48;                         // mov rax, jmpBackAddr
    Trampoline[hookLength + 1] = 0xB8;
    *(uintptr_t*)(Trampoline + hookLength + 2) = jmpBackAddr;
    Trampoline[hookLength + 10] = 0xFF;                    // jmp rax
    Trampoline[hookLength + 11] = 0xE0;

    VirtualProtect(src, hookLength, PAGE_EXECUTE_READWRITE, &oldProtect);
    src[0] = 0x48;
    src[1] = 0xB8;
    *(uintptr_t*)(src + 2) = (uintptr_t)dst;
    src[10] = 0xFF;
    src[11] = 0xE0;

    //for (size_t i = 12; i < hookLength; ++i)
      //  src[i] = 0x90;

    VirtualProtect(src, hookLength, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), src, hookLength);

    return Trampoline;
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
        std::println("[!] Vtable index {} is not readable at address {:p}", index, (void*)targetAddress);
    }
}
