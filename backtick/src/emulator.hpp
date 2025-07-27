#pragma once

#include <map>
#include <unordered_set>
#include <unordered_map>

#include <bochscpu.hpp>

#include "globals.hpp"

class Emulator {
public:
	Emulator();

	bool Initialize(const CpuState_t& State);

	void Run(const std::uint64_t EndAddress = 0);

	void Stop(int value) const { bochscpu_cpu_stop(Cpu_); }

	void Reset();

	const std::uint8_t* GetPhysicalPage(const std::uint64_t PhysicalAddress) const;

	bool VirtTranslate(const std::uint64_t Gva, std::uint64_t& Gpa) const;

	std::uint8_t* PhysTranslate(const std::uint64_t Gpa) const;

	bool VirtWrite(const std::uint64_t Gva, const uint8_t* Buffer,
		const uint64_t BufferSize);

	bool VirtWrite8(const std::uint64_t Gva, const std::uint64_t Value);

	bool VirtWrite4(const std::uint64_t Gva, const std::uint32_t Value);

	bool VirtWrite2(const std::uint64_t Gva, const std::uint16_t Value);

	bool VirtWrite1(const std::uint64_t Gva, const std::uint8_t Value);

	bool VirtRead(const std::uint64_t Gva, std::uint8_t* Buffer, const std::uint64_t BufferSize) const;

	std::uint64_t VirtRead8(std::uint64_t Gva) const;

	std::uint32_t VirtRead4(std::uint64_t Gva) const;

	std::uint16_t VirtRead2(std::uint64_t Gva) const;

	std::uint8_t VirtRead1(std::uint64_t Gva) const;

	void DirtyPhysicalMemoryRange(std::uint64_t Gpa, std::uint64_t Len);

	bool DirtyGpaPage(const std::uint64_t Gpa);

	const auto GetDirtedPage() const { return &DirtiedPage_; }

	bool SetReg(const Registers_t Reg, const REGVAL* Value);

	bool GetReg(const Registers_t Reg, REGVAL* Value) const;

	bool IsGvaMapped(std::uint64_t VirtualAddress) const;

	bool RunFromStatus(ULONG Status);

private:
	void LoadState(const CpuState_t& State);


	void PhyAccessHook(uint32_t,
		uint64_t PhysicalAddress, uintptr_t Len,
		uint32_t, uint32_t MemAccess);

	void AfterExecutionHook(uint32_t, void*);

	void BeforeExecutionHook(uint32_t, void* Ins);

	void LinAccessHook(uint32_t,
		uint64_t VirtualAddress,
		uint64_t PhysicalAddress, uintptr_t Len,
		uint32_t, uint32_t MemAccess);

	void InterruptHook(uint32_t, uint32_t Vector);

	void ExceptionHook(uint32_t,
		uint32_t Vector, uint32_t ErrorCode);

	void TlbControlHook(uint32_t,
		uint32_t What, uint64_t NewCrValue);

	static void StaticGpaMissingHandler(const std::uint64_t Gpa);

	static void StaticPhyAccessHook(void* Context, uint32_t Id, uint64_t PhysicalAddress,
		uintptr_t Len, uint32_t MemType, uint32_t MemAccess);

	static void StaticAfterExecutionHook(void* Context, uint32_t Id, void* Ins);

	static void StaticBeforeExecutionHook(void* Context, uint32_t Id, void* Ins);

	static void StaticLinAccessHook(void* Context, uint32_t Id, uint64_t VirtualAddress,
		uint64_t PhysicalAddress, uintptr_t Len,
		uint32_t MemType, uint32_t MemAccess);

	static void StaticInterruptHook(void* Context, uint32_t Id, uint32_t Vector);

	static void StaticExceptionHook(void* Context, uint32_t Id, uint32_t Vector,
		uint32_t ErrorCode);

	static void StaticTlbControlHook(void* Context, uint32_t Id, uint32_t What,
		uint64_t NewCrValue);

	static void StaticOpcodeHook(void* Context, uint32_t Id, const void* i,
		const uint8_t* opcode, uintptr_t len, bool is32,
		bool is64);

	static void StaticHltHook(void* Context, uint32_t Cpu);

	bochscpu_cpu_t Cpu_ = nullptr;

	bochscpu_hooks_t Hooks_ = {};

	bochscpu_hooks_t* HookChain_[2] = {};

	std::uint64_t InstructionExecutedCount_;

	std::uint64_t InstructionLimit_;

	std::uint64_t InitialCr3_ = 0;

	std::uint64_t ExecEndAddress_ = 0;

	std::unordered_set<std::uint64_t> MappedPhyPages_;

	std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> DirtiedPage_;

	bool Active_ = false;
};

using TimeFrames_t = std::map<unsigned int, CpuState_t>;

extern Emulator g_Emulator;

extern TimeFrames_t g_TimeFrames;