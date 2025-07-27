#include "../pch.h"

#include "utils.hpp"
#include "globals.hpp"
#include "debugger.hpp"

Debugger_t g_Debugger;

bool Debugger_t::Init() {
	char ExePathBuffer[MAX_PATH];
	if (!GetModuleFileNameA(nullptr, &ExePathBuffer[0],
		sizeof(ExePathBuffer))) {
		std::println("GetModuleFileNameA failed.");
		return false;
	}

	const fs::path ExePath(ExePathBuffer);
	const fs::path ParentDir(ExePath.parent_path());
	const std::vector<std::string_view> Dlls = { "dbghelp.dll", "symsrv.dll",
												"dbgeng.dll", "dbgcore.dll" };
	const fs::path DefaultDbgDllLocation(
		R"(c:\program Files (x86)\windows kits\10\debuggers\x64)");

    for (const auto& Dll : Dlls) {
        if (fs::exists(ParentDir / Dll)) {
            continue;
        }

        const fs::path DbgDllLocation(DefaultDbgDllLocation / Dll);
        if (!fs::exists(DbgDllLocation)) {

            std::println("The debugger class expects debug dlls in the "
                "directory "
                "where the application is running from.");
            return false;
        }

        fs::copy(DbgDllLocation, ParentDir);
        std::println("Copied {} into the "
            "executable directory..",
            DbgDllLocation.generic_string());
    }

    HRESULT Status = DebugCreate(__uuidof(IDebugClient), (void**)&Client_);
    if (FAILED(Status)) {
        std::println("DebugCreate failed with hr={:#x}", Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugControl), (void**)&Control_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugControl failed with hr={:#x}", Status);
        return false;
    }

    Status = Client_->QueryInterface(__uuidof(IDebugRegisters),
        (void**)&Registers_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugRegisters failed with hr={:#x}",
            Status);
        return false;
    }

    Status = Client_->QueryInterface(__uuidof(IDebugDataSpaces),
        (void**)&DataSpaces_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugDataSpaces failed with hr={:#x}",
            Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugSymbols3), (void**)&Symbols_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugSymbols failed with hr={:#x}", Status);
        return false;
    }

    return true;
}

void Debugger_t::Print(const char* Msg) {
    Control_->ControlledOutput(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, Msg);
}

bool Debugger_t::ReadVirtualMemory(const std::uint64_t VirtualAddress, const void* Buffer, std::size_t Size) const {
    ULONG BytesRead = 0;
    HRESULT Status = DataSpaces_->ReadVirtual(VirtualAddress, (uint8_t*)Buffer, Size, &BytesRead);

    return (BytesRead == Size && Status == S_OK);
}

bool Debugger_t::ReadPhysicalMemory(const std::uint64_t PhysicalAddress, const void* Buffer, std::size_t Size) {
    ULONG BytesRead = 0;
    HRESULT Status = DataSpaces_->ReadPhysical(PhysicalAddress, (uint8_t*)Buffer, Size, &BytesRead);

    return (BytesRead == Size && Status == S_OK);
}

bool Debugger_t::WritePhysicalMemory(const std::uint64_t PhysicalAddress, const void* Buffer, std::size_t Size) {
    ULONG BytesWritten = 0;
    HRESULT Status = DataSpaces_->WritePhysical(PhysicalAddress, (uint8_t*)Buffer, Size, &BytesWritten);

    return (BytesWritten == Size && Status == S_OK);
}

const std::uint8_t* Debugger_t::GetPhysicalPage(const std::uint64_t PhysicalAddress) {
    const auto AlignedPa = AlignPage(PhysicalAddress);
    
    if (!LoadedPhysicalPage_.contains(AlignedPa)) {

        auto Buffer = std::make_unique<std::uint8_t[]>(0x1000);

        ULONG BytesRead = 0;
        HRESULT Status = DataSpaces_->ReadPhysical(AlignedPa, Buffer.get(), 0x1000, &BytesRead);

        if (BytesRead != 0x1000 || Status != S_OK) {

            std::println("Reading physical memory {:#x} failed", PhysicalAddress);

            return nullptr;
        }

        LoadedPhysicalPage_[AlignedPa] = std::move(Buffer);
    }

    return LoadedPhysicalPage_.at(AlignedPa).get();
}

std::unordered_map<std::string, std::uint64_t>
Debugger_t::Regs64(const std::vector<std::string_view>& Targets) const {
    std::unordered_map<std::string, std::uint64_t> RegisterValues;
    RegisterValues.reserve(Targets.size());

    for (const auto& Name : Targets) {
        ULONG Index;
        if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
            std::println("Failed to get register {}", Name.data());
            RegisterValues.emplace(Name.data(), 0ull);
            continue;
        }

        DEBUG_VALUE RegValue;
        Registers_->GetValue(Index, &RegValue);
        RegisterValues.emplace(Name.data(), RegValue.I64);
    }

    return RegisterValues;
}

std::vector<DEBUG_VALUE>
Debugger_t::Regs(const std::vector<std::string_view>& Targets) const {
    std::vector<DEBUG_VALUE> RegisterValues;
    RegisterValues.reserve(Targets.size());

    for (const auto& Name : Targets) {
        ULONG Index;
        if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
            std::println("Failed to get register {}", Name.data());
            RegisterValues.push_back(DEBUG_VALUE{ 0 });
            continue;
        }

        DEBUG_VALUE RegValue;
        Registers_->GetValue(Index, &RegValue);
        RegisterValues.push_back(RegValue);
    }

    return RegisterValues;
}

std::uint64_t Debugger_t::Msr(std::uint32_t Index) const {
    ULONG64 Value;
    if (DataSpaces_->ReadMsr(Index, &Value) != S_OK) {
        std::println("Failed to read msr: {:#x}", Index);
        return 0;
    }

    return Value;
}

bool Debugger_t::SetReg64(std::string_view Name, std::uint64_t Value) {
    ULONG Index;
    if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
        std::println("Failed to get register {}", Name.data());
        return false;
    }

    DEBUG_VALUE RegValue {};
    RegValue.I64 = Value;
    RegValue.Type = DEBUG_VALUE_INT64;
    if (auto Status = Registers_->SetValue(Index, &RegValue); Status != S_OK) {
        std::println("SetValue failed with {:#x}", (unsigned long)Status);
        return false;
    }

    return true;
}

std::uint64_t Debugger_t::Reg64(std::string_view Name) const {
    ULONG Index;
    if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
        std::println("Failed to get register {}", Name.data());
        return 0;
    }

    DEBUG_VALUE RegValue;
    Registers_->GetValue(Index, &RegValue);

    return RegValue.I64;
}

Seg_t Debugger_t::GdtEntry(std::uint64_t Base, std::uint16_t Limit, std::uint64_t Selector) const {
    auto Ti = Selector >> 2 & 1;
    if (Ti) {
        std::println("Expected a GDT table indicator when reading segment descriptor");
        return {};
    }

    auto Index = Selector >> 3 & ((1ULL << 13) - 1);
    std::uint64_t GdtLimit = Limit;
    if ((GdtLimit + 1) % 8 != 0) {
        std::println("Invalid GDT limit {:#x}", GdtLimit);
        return {};
    }

    auto MaxIndex = (GdtLimit + 1) / 8;
    if(Index >= MaxIndex) {
        std::println("The selector {:#x} has an index ({:#x}) larger than the maximum allowed ({:#})",
            Selector,
            Index,
            MaxIndex);
    }

    std::array<std::uint8_t, 16> Descriptor;

    const auto EntryAddr = Base + (Index * 8);
    ReadVirtualMemory(EntryAddr, Descriptor.data(), 16);

    return Seg_t(Selector, Descriptor);
}

bool Debugger_t::LoadCpuState(const CpuState_t& State) {
    SetReg64("rax", State.Rax);
    SetReg64("rbx", State.Rbx);
    SetReg64("rcx", State.Rcx);
    SetReg64("rdx", State.Rdx);
    SetReg64("rsi", State.Rsi);
    SetReg64("rdi", State.Rdi);
    SetReg64("rip", State.Rip);
    SetReg64("rsp", State.Rsp);
    SetReg64("rbp", State.Rbp);
    SetReg64("r8", State.R8);
    SetReg64("r9", State.R9);
    SetReg64("r10", State.R10);
    SetReg64("r11", State.R11);
    SetReg64("r12", State.R12);
    SetReg64("r13", State.R13);
    SetReg64("r14", State.R14);
    SetReg64("r15", State.R15);
    SetReg64("fpcw", State.Fpcw);
    SetReg64("fpsw", State.Fpsw);
    SetReg64("cr0", State.Cr0.Flags);
    SetReg64("cr0", State.Cr0.Flags);
    SetReg64("cr2", State.Cr2);
    SetReg64("cr3", State.Cr3);
    SetReg64("cr4", State.Cr4.Flags);
    SetReg64("cr8", State.Cr8);
    SetReg64("xcr0", State.Xcr0);
    SetReg64("dr0", State.Dr0);
    SetReg64("dr1", State.Dr1);
    SetReg64("dr2", State.Dr2);
    SetReg64("dr3", State.Dr3);
    SetReg64("dr6", State.Dr6);
    SetReg64("dr7", State.Dr7);
    SetReg64("mxcsr", State.Mxcsr);

    SetReg64("efl", State.Rflags);
    SetReg64("fptw", State.Fptw.Value);

    //TODO: fpst, segment and sse.
   
    return true;
}

bool Debugger_t::DumpCpuState(CpuState_t& State) const {
    // TODO: stiol faild while trying to emulate studd using this.

    State.Rax   = Reg64("rax");
    State.Rbx   = Reg64("rbx");
    State.Rcx   = Reg64("rcx");
    State.Rdx   = Reg64("rdx");
    State.Rsi   = Reg64("rsi");
    State.Rdi   = Reg64("rdi");
    State.Rip   = Reg64("rip");
    State.Rsp   = Reg64("rsp");
    State.Rbp   = Reg64("rbp");
    State.R8    = Reg64("r8");
    State.R9    = Reg64("r9");
    State.R10   = Reg64("r10");
    State.R11   = Reg64("r11");
    State.R12   = Reg64("r12");
    State.R13   = Reg64("r13");
    State.R14   = Reg64("r14");
    State.R15   = Reg64("r15");
    State.Fpcw  = Reg64("fpcw");
    State.Fpsw  = Reg64("fpsw");
    State.Cr0.Flags = Reg64("cr0");
    State.Cr2   = Reg64("cr2");
    State.Cr3   = Reg64("cr3");
    State.Cr4.Flags = Reg64("cr4");
    State.Cr8   = Reg64("cr8");
    State.Xcr0  = Reg64("xcr0");
    State.Dr0 = Reg64("dr0");
    State.Dr1 = Reg64("dr1");
    State.Dr2 = Reg64("dr2");
    State.Dr3 = Reg64("dr3");
    State.Dr6 = Reg64("dr6");
    State.Dr7 = Reg64("dr7");
    State.Mxcsr = Reg64("mxcsr");

    State.Rflags = Reg64("efl");
    State.Fptw   = Reg64("fptw");
    State.Fpop   = 0;
    State.MxcsrMask = 0xffbf;

    const auto& Fpst = Regs({
        "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"
    });

    for (auto i = 0; i < Fpst.size(); i++) {
        State.Fpst[i] = Fpst[i];
    }

    State.Tsc           = Msr(msr::TSC);
    State.ApicBase      = Msr(msr::IA32_APIC_BASE);
    State.SysenterCs    = Msr(msr::IA32_SYSENTER_CS);
    State.SysenterEsp   = Msr(msr::SYSENTER_ESP_MSR);
    State.SysenterEip   = Msr(msr::SYSENTER_EIP_MSR);
    State.Pat           = Msr(msr::IA32_PAT);
    State.Efer          = Msr(msr::IA32_EFER);
    State.Star          = Msr(msr::IA32_STAR);
    State.Lstar         = Msr(msr::IA32_LSTAR);
    State.Cstar         = Msr(msr::IA32_CSTAR);
    State.Sfmask        = Msr(msr::IA32_FMASK);
    State.KernelGsBase  = Msr(msr::IA32_KERNEL_GSBASE);
    State.TscAux        = Msr(msr::IA32_TSC_AUX);

    std::uint64_t GdtBase = Reg64("gdtr");
    std::uint16_t GdtLimit = Reg64("gdtl");

    State.Gdtr = GlobalSeg_t(Reg64("gdtr"), Reg64("gdtl"));
    State.Idtr = GlobalSeg_t(Reg64("idtr"), Reg64("idtl"));

    State.Es    = GdtEntry(GdtBase, GdtLimit, Reg64("es"));
    State.Cs    = GdtEntry(GdtBase, GdtLimit, Reg64("cs"));
    State.Ss    = GdtEntry(GdtBase, GdtLimit, Reg64("ss"));
    State.Ds    = GdtEntry(GdtBase, GdtLimit, Reg64("ds"));
    State.Tr    = GdtEntry(GdtBase, GdtLimit, Reg64("tr"));
    State.Gs    = GdtEntry(GdtBase, GdtLimit, Reg64("gs"));
    State.Fs    = GdtEntry(GdtBase, GdtLimit, Reg64("fs"));
    State.Ldtr  = GdtEntry(GdtBase, GdtLimit, Reg64("ldtr"));

    State.Gs.Base = Msr(msr::IA32_GS_BASE);
    State.Fs.Base = Msr(msr::IA32_FS_BASE);

    const auto& Sse = Regs({
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
        "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
    });

    for (int i = 0; i < Sse.size(); i++) {
        State.Zmm[i] = Sse[i];
    }
}