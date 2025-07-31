
#include "utils.hpp"

#include <fstream>
#include <nlohmann/json.hpp>

#include "globals.hpp"

namespace json = nlohmann;

std::uint64_t ScanPattern(const std::vector<int>& pattern, std::uint64_t maxScanLength) {
    std::uint64_t baseAddr = (std::uint64_t)GetModuleHandleA("dbgeng.dll");
    for (std::uint64_t i = 0; i < maxScanLength; i++) {
        bool found = true;

        for (size_t j = 0; j < pattern.size(); j++) {
            if (pattern[j] != -1 && *(std::uint8_t*)(baseAddr + i + j) != pattern[j]) {
                found = false;
                break;
            }
        }

        if (found) return baseAddr + i;
    }

    return -1;
}

std::uint64_t ScanPattern(const std::string& pattern, std::uint64_t maxScanLength) {
    std::stringstream ss_pattern(pattern);
    std::string token;
    std::vector<int> processed_pattern;
    while (ss_pattern >> token) {
        if (token.starts_with("?")) {
            processed_pattern.push_back(-1);
        }
        else {
            processed_pattern.push_back(std::stoi(token, nullptr, 16));
        }
    }
    return ScanPattern(processed_pattern, maxScanLength);
}

void Hexdump(const void* data, size_t size) {
    const unsigned char* byteData = static_cast<const unsigned char*>(data);
    constexpr size_t bytesPerLine = 16;

    for (size_t i = 0; i < size; i += bytesPerLine) {
        std::print("{:08x}: ", i);

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                std::print("{:02x} ", byteData[i + j]);
            } else {
                std::print("   ");
            }
        }

        std::print(" ");

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                std::print("{}", std::isprint(c) ? static_cast<char>(c) : '.');
            }
        }

        std::print("\n");
    }
}

bool LoadCpuStateFromJSON(CpuState_t& CpuState, const fs::path& CpuStatePath) {
    std::ifstream File(CpuStatePath);
    json::json Json;
    File >> Json;

    memset(&CpuState, 0, sizeof(CpuState));

#define REGISTER_OR(_Dmp_, _Btk_, _Value_)                                                                         \
    {                                                                                                              \
        CpuState._Btk_ = decltype(CpuState._Btk_)(std::strtoull(Json.value(#_Dmp_, _Value_).c_str(), nullptr, 0)); \
    }

#define REGISTER(_Dmp_, _Btk_)                                                                                         \
    {                                                                                                                  \
        CpuState._Btk_ = decltype(CpuState._Btk_)(std::strtoull(Json[#_Dmp_].get<std::string>().c_str(), nullptr, 0)); \
    }

    REGISTER(rax, Rax)
    REGISTER(rbx, Rbx)
    REGISTER(rcx, Rcx)
    REGISTER(rdx, Rdx)
    REGISTER(rsi, Rsi)
    REGISTER(rdi, Rdi)
    REGISTER(rip, Rip)
    REGISTER(rsp, Rsp)
    REGISTER(rbp, Rbp)
    REGISTER(r8, R8)
    REGISTER(r9, R9)
    REGISTER(r10, R10)
    REGISTER(r11, R11)
    REGISTER(r12, R12)
    REGISTER(r13, R13)
    REGISTER(r14, R14)
    REGISTER(r15, R15)
    REGISTER(rflags, Rflags)
    REGISTER(tsc, Tsc)
    REGISTER(apic_base, ApicBase)
    REGISTER(sysenter_cs, SysenterCs)
    REGISTER(sysenter_esp, SysenterEsp)
    REGISTER(sysenter_eip, SysenterEip)
    REGISTER(pat, Pat)
    REGISTER(efer, Efer.Flags)
    REGISTER(star, Star)
    REGISTER(lstar, Lstar)
    REGISTER(cstar, Cstar)
    REGISTER(sfmask, Sfmask)
    REGISTER(kernel_gs_base, KernelGsBase)
    REGISTER(tsc_aux, TscAux)
    REGISTER(fpcw, Fpcw)
    REGISTER(fpsw, Fpsw)
    REGISTER(cr0, Cr0.Flags)
    REGISTER(cr2, Cr2)
    REGISTER(cr3, Cr3)
    REGISTER(cr4, Cr4.Flags)
    REGISTER(cr8, Cr8)
    REGISTER(xcr0, Xcr0)
    REGISTER(dr0, Dr0)
    REGISTER(dr1, Dr1)
    REGISTER(dr2, Dr2)
    REGISTER(dr3, Dr3)
    REGISTER(dr6, Dr6)
    REGISTER(dr7, Dr7)
    REGISTER(mxcsr, Mxcsr)
    // REGISTER(mxcsr_mask, MxcsrMask)
    // REGISTER(fpop, Fpop)
    // REGISTER_OR(cet_control_u, CetControlU, "0")
    // REGISTER_OR(cet_control_s, CetControlS, "0")
    // REGISTER_OR(pl0_ssp, Pl0Ssp, "0")
    // REGISTER_OR(pl1_ssp, Pl1Ssp, "0")
    // REGISTER_OR(pl2_ssp, Pl2Ssp, "0")
    // REGISTER_OR(pl3_ssp, Pl3Ssp, "0")
    // REGISTER_OR(interrupt_ssp_table, InterruptSspTable, "0")
    // REGISTER_OR(ssp, Ssp, "0")
#undef REGISTER_OR
#undef REGISTER

#define SEGMENT(_Dmp_, _Btk_)                                                                                          \
    {                                                                                                                  \
        CpuState._Btk_.Present = Json[#_Dmp_]["present"].get<bool>();                                                  \
        CpuState._Btk_.Selector = decltype(CpuState._Btk_.Selector)(                                                   \
            std::strtoull(Json[#_Dmp_]["selector"].get<std::string>().c_str(), nullptr, 0));                           \
        CpuState._Btk_.Base = std::strtoull(Json[#_Dmp_]["base"].get<std::string>().c_str(), nullptr, 0);              \
        CpuState._Btk_.Limit = decltype(CpuState._Btk_.Limit)(                                                         \
            std::strtoull(Json[#_Dmp_]["limit"].get<std::string>().c_str(), nullptr, 0));                              \
        CpuState._Btk_.Attr =                                                                                          \
            decltype(CpuState._Btk_.Attr)(std::strtoull(Json[#_Dmp_]["attr"].get<std::string>().c_str(), nullptr, 0)); \
    }

    SEGMENT(es, Es)
    SEGMENT(cs, Cs)
    SEGMENT(ss, Ss)
    SEGMENT(ds, Ds)
    SEGMENT(fs, Fs)
    SEGMENT(gs, Gs)
    SEGMENT(tr, Tr)
    SEGMENT(ldtr, Ldtr)
#undef SEGMENT

#define GLOBALSEGMENT(_Dmp_, _Btk_)                                                                                    \
    {                                                                                                                  \
        CpuState._Btk_.Base =                                                                                          \
            decltype(CpuState._Btk_.Base)(std::strtoull(Json[#_Dmp_]["base"].get<std::string>().c_str(), nullptr, 0)); \
        CpuState._Btk_.Limit = decltype(CpuState._Btk_.Limit)(                                                         \
            std::strtoull(Json[#_Dmp_]["limit"].get<std::string>().c_str(), nullptr, 0));                              \
    }

    GLOBALSEGMENT(gdtr, Gdtr)
    GLOBALSEGMENT(idtr, Idtr)
#undef GLOBALSEGMENT

    bool BdumpGenerated = false;
    for (size_t Idx = 0; Idx < 8; Idx++) {
        std::optional<uint64_t> Fraction = 0;
        std::optional<uint16_t> Exp = 0;

        if (Json["fpst"][Idx].is_string()) {
            const std::string& Value = Json["fpst"][Idx].get<std::string>();
            const bool Infinity = Value.find("Infinity") != Value.npos;
            if (!Infinity) {
                std::print(
                    "There is a fpst register that isn't set to 0xInfinity "
                    "which should not happen, bailing.");
                return false;
            }

            BdumpGenerated = true;
        } else {
            Fraction = std::strtoull(Json["fpst"][Idx]["fraction"].get<std::string>().c_str(), nullptr, 0);
            Exp = uint16_t(std::strtoull(Json["fpst"][Idx]["exp"].get<std::string>().c_str(), nullptr, 0));
        }

        CpuState.Fpst[Idx].fraction = Fraction.value_or(0);
        CpuState.Fpst[Idx].exp = Exp.value_or(0);
    }

    CpuState.Fptw = Fptw_t(uint16_t(std::strtoull(Json["fptw"].get<std::string>().c_str(), nullptr, 0)));

    if (BdumpGenerated) {
        const auto Fptw = Fptw_t::FromAbridged(CpuState.Fptw.Value);
        std::print("Setting @fptw to {:#x} as this is an old dump taken with bdump..\n", Fptw.Value);
        CpuState.Fptw = Fptw;
    }

    return true;
}