#pragma once

#include <cstdint>
#include <filesystem>

#include "debugger.hpp"

namespace fs = std::filesystem;

constexpr std::uint64_t AlignPage(std::uint64_t Address) {
	return Address & ~0xfff;
}

void Hexdump(const void* data, size_t size);

struct CpuState_t;

bool LoadCpuStateFromJSON(CpuState_t& CpuState, const fs::path& CpuStatePath);