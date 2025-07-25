
#include "../pch.h"

#include "utils.hpp"
#include "debugger.hpp"

Debugger_t g_Debugger;

[[nodiscard]] bool Debugger_t::Init() {
	std::println(
		"Initializing the debugger instance.. (this takes a bit of time)");

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

std::unordered_map<std::string, DEBUG_VALUE>
Debugger_t::Regs(const std::vector<std::string_view>& Targets) const {
    std::unordered_map<std::string, DEBUG_VALUE> RegisterValues;
    RegisterValues.reserve(Targets.size());

    for (const auto& Name : Targets) {
        ULONG Index;
        if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
            std::println("Failed to get register {}", Name.data());
            RegisterValues.emplace(Name.data(), DEBUG_VALUE{ 0 });
            continue;
        }

        DEBUG_VALUE RegValue;
        Registers_->GetValue(Index, &RegValue);
        RegisterValues.emplace(Name.data(), RegValue);
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

bool Debugger_t::LoadCpuState(const CpuState_t& State) {
    // TODO
}

bool Debugger_t::DumpCpuState(CpuState_t& State) const {
    // TODO
}