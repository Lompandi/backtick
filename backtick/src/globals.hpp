#pragma once

#include <array>

#include "../pch.h"
#include "utils.hpp"

#include <bochscpu.hpp>

extern EXT_API_VERSION g_ExtApiVersion;

extern WINDBG_EXTENSION_APIS ExtensionApis;

//
// Determin whether the user is currently in shadow state where emulator operation is accessable.
//
extern bool InShadowState;

union MMPTE_HARDWARE {
    struct {
        uint64_t Present : 1;
        uint64_t Write : 1;
        uint64_t UserAccessible : 1;
        uint64_t WriteThrough : 1;
        uint64_t CacheDisable : 1;
        uint64_t Accessed : 1;
        uint64_t Dirty : 1;
        uint64_t LargePage : 1;
        uint64_t Available : 4;
        uint64_t PageFrameNumber : 36;
        uint64_t ReservedForHardware : 4;
        uint64_t ReservedForSoftware : 11;
        uint64_t NoExecute : 1;
    } u;
    uint64_t AsUINT64;
    constexpr MMPTE_HARDWARE(const uint64_t Value) : AsUINT64(Value) {}
};

//
// Structure to parse a virtual address.
//

union VIRTUAL_ADDRESS {
    struct {
        uint64_t Offset : 12;
        uint64_t PtIndex : 9;
        uint64_t PdIndex : 9;
        uint64_t PdPtIndex : 9;
        uint64_t Pml4Index : 9;
        uint64_t Reserved : 16;
    } u;
    uint64_t AsUINT64;
    constexpr VIRTUAL_ADDRESS(const uint64_t Value) : AsUINT64(Value) {}
};


struct Zmm_t {
    uint64_t Q[8];

    Zmm_t() { memset(this, 0, sizeof(decltype(*this))); }

    Zmm_t(const DEBUG_VALUE& Val) { memcpy(this, &Val.F128Bytes, 16); }

    bool operator==(const Zmm_t& B) const {
        bool Equal = true;
        for (size_t Idx = 0; Idx < 8; Idx++) {
            Equal = Equal && Q[Idx] == B.Q[Idx];
        }
        return Equal;
    }
};

template <typename T>
bool ExtractBit(const T& data, unsigned int bit_pos) {
    if constexpr (std::is_integral_v<T>) {
        if (bit_pos >= sizeof(T) * 8)
            throw std::out_of_range("bit_pos out of range");
        return (static_cast<std::make_unsigned_t<T>>(data) >> bit_pos) & 1u;
    }
    else {
        static_assert(std::is_same_v<typename T::value_type, uint8_t>, "Container must hold uint8_t");

        if (bit_pos >= data.size() * 8)
            throw std::out_of_range("bit_pos out of range");

        size_t byte_index = bit_pos / 8;
        size_t bit_index = bit_pos % 8;

        return (data[byte_index] >> bit_index) & 1u;
    }
}

template <typename Container>
uint64_t ExtractBits(const Container& data, unsigned int from, unsigned int to) {
    if (from > to) throw std::out_of_range("Invalid bit range");
    if (to >= data.size() * 8) throw std::out_of_range("Bit range exceeds data size");

    unsigned int start_byte = from / 8;
    unsigned int end_byte = to / 8;
    unsigned int num_bytes = end_byte - start_byte + 1;

    if (num_bytes > 8)
        throw std::out_of_range("Bit range too large to fit in uint64_t");

    uint64_t val = 0;
    std::memcpy(&val, &data[start_byte], num_bytes);

    unsigned int bit_offset = from % 8;
    unsigned int width = to - from + 1;

    val >>= bit_offset;
    uint64_t mask = (uint64_t(1) << width) - 1;
    return val & mask;
}

struct Seg_t {
    uint16_t Selector;
    uint64_t Base;
    uint32_t Limit;
    union {
        struct {
            uint16_t SegmentType : 4;
            uint16_t NonSystemSegment : 1;
            uint16_t DescriptorPrivilegeLevel : 2;
            uint16_t Present : 1;
            uint16_t Reserved : 4;
            uint16_t Available : 1;
            uint16_t Long : 1;
            uint16_t Default : 1;
            uint16_t Granularity : 1;
        };

        uint16_t Attr;
    };

    Seg_t() { memset(this, 0, sizeof(decltype(*this))); }

    static Seg_t FromDescriptor(std::uint64_t Selector, const std::array<std::uint8_t, 16>& Value);

    bool operator==(const Seg_t& B) const {
        bool Equal = Attr == B.Attr;
        Equal = Equal && Base == B.Base;
        Equal = Equal && Limit == B.Limit;
        Equal = Equal && Present == B.Present;
        Equal = Equal && Selector == B.Selector;
        return Equal;
    }
};

struct GlobalSeg_t {
    uint64_t Base;
    uint16_t Limit;

    GlobalSeg_t() { memset(this, 0, sizeof(decltype(*this))); }

    GlobalSeg_t(std::uint64_t B, std::uint16_t Lim)
        : Base(B), Limit(Lim) { }

    bool operator==(const GlobalSeg_t& B) const {
        bool Equal = Base == B.Base;
        Equal = Equal && Limit == B.Limit;
        return Equal;
    }
};

union Cr0_t {
    Cr0_t() { Flags = 0; }

    Cr0_t(const uint64_t Value) { Flags = Value; }

    bool operator==(const Cr0_t& B) const { return Flags == B.Flags; }

    void Print() const {
        std::print("CR0: {:#x}\n", Flags);
        std::print("CR0.ProtectionEnable: {}\n", ProtectionEnable);
        std::print("CR0.MonitorCoprocessor: {}\n", MonitorCoprocessor);
        std::print("CR0.EmulateFpu: {}\n", EmulateFpu);
        std::print("CR0.TaskSwitched: {}\n", TaskSwitched);
        std::print("CR0.ExtensionType: {}\n", ExtensionType);
        std::print("CR0.NumericError: {}\n", NumericError);
        std::print("CR0.WriteProtect: {}\n", WriteProtect);
        std::print("CR0.AlignmentMask: {}\n", AlignmentMask);
        std::print("CR0.NotWriteThrough: {}\n", NotWriteThrough);
        std::print("CR0.CacheDisable: {}\n", CacheDisable);
        std::print("CR0.PagingEnable: {}\n", PagingEnable);
    }

    struct {
        uint64_t ProtectionEnable : 1;
#define CR0_PROTECTION_ENABLE_BIT 0
#define CR0_PROTECTION_ENABLE_FLAG 0x01
#define CR0_PROTECTION_ENABLE(_) (((_) >> 0) & 0x01)

       
        uint64_t MonitorCoprocessor : 1;
#define CR0_MONITOR_COPROCESSOR_BIT 1
#define CR0_MONITOR_COPROCESSOR_FLAG 0x02
#define CR0_MONITOR_COPROCESSOR(_) (((_) >> 1) & 0x01)

      
        uint64_t EmulateFpu : 1;
#define CR0_EMULATE_FPU_BIT 2
#define CR0_EMULATE_FPU_FLAG 0x04
#define CR0_EMULATE_FPU(_) (((_) >> 2) & 0x01)

        
        uint64_t TaskSwitched : 1;
#define CR0_TASK_SWITCHED_BIT 3
#define CR0_TASK_SWITCHED_FLAG 0x08
#define CR0_TASK_SWITCHED(_) (((_) >> 3) & 0x01)

       
        uint64_t ExtensionType : 1;
#define CR0_EXTENSION_TYPE_BIT 4
#define CR0_EXTENSION_TYPE_FLAG 0x10
#define CR0_EXTENSION_TYPE(_) (((_) >> 4) & 0x01)

       
        uint64_t NumericError : 1;
#define CR0_NUMERIC_ERROR_BIT 5
#define CR0_NUMERIC_ERROR_FLAG 0x20
#define CR0_NUMERIC_ERROR(_) (((_) >> 5) & 0x01)
        uint64_t Reserved1 : 10;

       
        uint64_t WriteProtect : 1;
#define CR0_WRITE_PROTECT_BIT 16
#define CR0_WRITE_PROTECT_FLAG 0x10000
#define CR0_WRITE_PROTECT(_) (((_) >> 16) & 0x01)
        uint64_t Reserved2 : 1;

        
        uint64_t AlignmentMask : 1;
#define CR0_ALIGNMENT_MASK_BIT 18
#define CR0_ALIGNMENT_MASK_FLAG 0x40000
#define CR0_ALIGNMENT_MASK(_) (((_) >> 18) & 0x01)
        uint64_t Reserved3 : 10;

       
        uint64_t NotWriteThrough : 1;
#define CR0_NOT_WRITE_THROUGH_BIT 29
#define CR0_NOT_WRITE_THROUGH_FLAG 0x20000000
#define CR0_NOT_WRITE_THROUGH(_) (((_) >> 29) & 0x01)

        
        uint64_t CacheDisable : 1;
#define CR0_CACHE_DISABLE_BIT 30
#define CR0_CACHE_DISABLE_FLAG 0x40000000
#define CR0_CACHE_DISABLE(_) (((_) >> 30) & 0x01)

       
        uint64_t PagingEnable : 1;
#define CR0_PAGING_ENABLE_BIT 31
#define CR0_PAGING_ENABLE_FLAG 0x80000000
#define CR0_PAGING_ENABLE(_) (((_) >> 31) & 0x01)
        uint64_t Reserved4 : 32;
    };

    uint64_t Flags;
};

union Cr4_t {
    Cr4_t() { Flags = 0; }

    Cr4_t(const uint64_t Value) { Flags = Value; }

    bool operator==(const Cr4_t& B) const { return Flags == B.Flags; }

    void Print() const {
        std::print("CR4: {:#x}\n", Flags);
        std::print("CR4.VirtualModeExtensions: {}\n", VirtualModeExtensions);
        std::print("CR4.ProtectedModeVirtualInterrupts: {}\n",
            ProtectedModeVirtualInterrupts);
        std::print("CR4.TimestampDisable: {}\n", TimestampDisable);
        std::print("CR4.DebuggingExtensions: {}\n", DebuggingExtensions);
        std::print("CR4.PageSizeExtensions: {}\n", PageSizeExtensions);
        std::print("CR4.PhysicalAddressExtension: {}\n", PhysicalAddressExtension);
        std::print("CR4.MachineCheckEnable: {}\n", MachineCheckEnable);
        std::print("CR4.PageGlobalEnable: {}\n", PageGlobalEnable);
        std::print("CR4.PerformanceMonitoringCounterEnable: {}\n",
            PerformanceMonitoringCounterEnable);
        std::print("CR4.OsFxsaveFxrstorSupport: {}\n", OsFxsaveFxrstorSupport);
        std::print("CR4.OsXmmExceptionSupport: {}\n", OsXmmExceptionSupport);
        std::print("CR4.UsermodeInstructionPrevention: {}\n",
            UsermodeInstructionPrevention);
        std::print("CR4.LA57: {}\n", LA57);
        std::print("CR4.VmxEnable: {}\n", VmxEnable);
        std::print("CR4.SmxEnable: {}\n", SmxEnable);
        std::print("CR4.FsgsbaseEnable: {}\n", FsgsbaseEnable);
        std::print("CR4.PcidEnable: {}\n", PcidEnable);
        std::print("CR4.OsXsave: {}\n", OsXsave);
        std::print("CR4.SmepEnable: {}\n", SmepEnable);
        std::print("CR4.SmapEnable: {}\n", SmapEnable);
        std::print("CR4.ProtectionKeyEnable: {}\n", ProtectionKeyEnable);
    }

    struct {
       
        uint64_t VirtualModeExtensions : 1;
#define CR4_VIRTUAL_MODE_EXTENSIONS_BIT 0
#define CR4_VIRTUAL_MODE_EXTENSIONS_FLAG 0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS(_) (((_) >> 0) & 0x01)

        
        uint64_t ProtectedModeVirtualInterrupts : 1;
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_BIT 1
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_FLAG 0x02
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS(_) (((_) >> 1) & 0x01)

       
        uint64_t TimestampDisable : 1;
#define CR4_TIMESTAMP_DISABLE_BIT 2
#define CR4_TIMESTAMP_DISABLE_FLAG 0x04
#define CR4_TIMESTAMP_DISABLE(_) (((_) >> 2) & 0x01)

        
        uint64_t DebuggingExtensions : 1;
#define CR4_DEBUGGING_EXTENSIONS_BIT 3
#define CR4_DEBUGGING_EXTENSIONS_FLAG 0x08
#define CR4_DEBUGGING_EXTENSIONS(_) (((_) >> 3) & 0x01)

        uint64_t PageSizeExtensions : 1;
#define CR4_PAGE_SIZE_EXTENSIONS_BIT 4
#define CR4_PAGE_SIZE_EXTENSIONS_FLAG 0x10
#define CR4_PAGE_SIZE_EXTENSIONS(_) (((_) >> 4) & 0x01)

       
        uint64_t PhysicalAddressExtension : 1;
#define CR4_PHYSICAL_ADDRESS_EXTENSION_BIT 5
#define CR4_PHYSICAL_ADDRESS_EXTENSION_FLAG 0x20
#define CR4_PHYSICAL_ADDRESS_EXTENSION(_) (((_) >> 5) & 0x01)

       
        uint64_t MachineCheckEnable : 1;
#define CR4_MACHINE_CHECK_ENABLE_BIT 6
#define CR4_MACHINE_CHECK_ENABLE_FLAG 0x40
#define CR4_MACHINE_CHECK_ENABLE(_) (((_) >> 6) & 0x01)

       
        uint64_t PageGlobalEnable : 1;
#define CR4_PAGE_GLOBAL_ENABLE_BIT 7
#define CR4_PAGE_GLOBAL_ENABLE_FLAG 0x80
#define CR4_PAGE_GLOBAL_ENABLE(_) (((_) >> 7) & 0x01)

        
        uint64_t PerformanceMonitoringCounterEnable : 1;
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_BIT 8
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_FLAG 0x100
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE(_) (((_) >> 8) & 0x01)

       
        uint64_t OsFxsaveFxrstorSupport : 1;
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_BIT 9
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_FLAG 0x200
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT(_) (((_) >> 9) & 0x01)

        
        uint64_t OsXmmExceptionSupport : 1;
#define CR4_OS_XMM_EXCEPTION_SUPPORT_BIT 10
#define CR4_OS_XMM_EXCEPTION_SUPPORT_FLAG 0x400
#define CR4_OS_XMM_EXCEPTION_SUPPORT(_) (((_) >> 10) & 0x01)

        
        uint64_t UsermodeInstructionPrevention : 1;
#define CR4_USERMODE_INSTRUCTION_PREVENTION_BIT 11
#define CR4_USERMODE_INSTRUCTION_PREVENTION_FLAG 0x800
#define CR4_USERMODE_INSTRUCTION_PREVENTION(_) (((_) >> 11) & 0x01)

        uint64_t LA57 : 1;
#define CR4_LA57_BIT 12
#define CR4_LA57_FLAG 0x1000
#define CR4_LA57(_) (((_) >> 12) & 0x01)

        
        uint64_t VmxEnable : 1;
#define CR4_VMX_ENABLE_BIT 13
#define CR4_VMX_ENABLE_FLAG 0x2000
#define CR4_VMX_ENABLE(_) (((_) >> 13) & 0x01)

        
        uint64_t SmxEnable : 1;
#define CR4_SMX_ENABLE_BIT 14
#define CR4_SMX_ENABLE_FLAG 0x4000
#define CR4_SMX_ENABLE(_) (((_) >> 14) & 0x01)
        uint64_t Reserved2 : 1;

        
        uint64_t FsgsbaseEnable : 1;
#define CR4_FSGSBASE_ENABLE_BIT 16
#define CR4_FSGSBASE_ENABLE_FLAG 0x10000
#define CR4_FSGSBASE_ENABLE(_) (((_) >> 16) & 0x01)

      
        uint64_t PcidEnable : 1;
#define CR4_PCID_ENABLE_BIT 17
#define CR4_PCID_ENABLE_FLAG 0x20000
#define CR4_PCID_ENABLE(_) (((_) >> 17) & 0x01)

       
        uint64_t OsXsave : 1;
#define CR4_OS_XSAVE_BIT 18
#define CR4_OS_XSAVE_FLAG 0x40000
#define CR4_OS_XSAVE(_) (((_) >> 18) & 0x01)
        uint64_t Reserved3 : 1;

        
        uint64_t SmepEnable : 1;
#define CR4_SMEP_ENABLE_BIT 20
#define CR4_SMEP_ENABLE_FLAG 0x100000
#define CR4_SMEP_ENABLE(_) (((_) >> 20) & 0x01)

       
        uint64_t SmapEnable : 1;
#define CR4_SMAP_ENABLE_BIT 21
#define CR4_SMAP_ENABLE_FLAG 0x200000
#define CR4_SMAP_ENABLE(_) (((_) >> 21) & 0x01)

       
        uint64_t ProtectionKeyEnable : 1;
#define CR4_PROTECTION_KEY_ENABLE_BIT 22
#define CR4_PROTECTION_KEY_ENABLE_FLAG 0x400000
#define CR4_PROTECTION_KEY_ENABLE(_) (((_) >> 22) & 0x01)
        uint64_t Reserved4 : 41;
    };

    uint64_t Flags;
};

union Efer_t {
    Efer_t() { Flags = 0; }

    Efer_t(const uint64_t Value) { Flags = Value; }

    bool operator==(const Efer_t& B) const { return Flags == B.Flags; }

    void Print() const {
        std::print("EFER: {:#x}\n", Flags);
        std::print("EFER.SyscallEnable: {}\n", SyscallEnable);
        std::print("EFER.Ia32EModeEnable: {}\n", Ia32EModeEnable);
        std::print("EFER.Ia32EModeActive: {}\n", Ia32EModeActive);
        std::print("EFER.ExecuteDisableBitEnable: {}\n", ExecuteDisableBitEnable);
    }

    struct {
       
        uint64_t SyscallEnable : 1;
#define IA32_EFER_SYSCALL_ENABLE_BIT 0
#define IA32_EFER_SYSCALL_ENABLE_FLAG 0x01
#define IA32_EFER_SYSCALL_ENABLE(_) (((_) >> 0) & 0x01)
        uint64_t Reserved1 : 7;

        uint64_t Ia32EModeEnable : 1;
#define IA32_EFER_IA32E_MODE_ENABLE_BIT 8
#define IA32_EFER_IA32E_MODE_ENABLE_FLAG 0x100
#define IA32_EFER_IA32E_MODE_ENABLE(_) (((_) >> 8) & 0x01)
        uint64_t Reserved2 : 1;

        
        uint64_t Ia32EModeActive : 1;
#define IA32_EFER_IA32E_MODE_ACTIVE_BIT 10
#define IA32_EFER_IA32E_MODE_ACTIVE_FLAG 0x400
#define IA32_EFER_IA32E_MODE_ACTIVE(_) (((_) >> 10) & 0x01)

        
        uint64_t ExecuteDisableBitEnable : 1;
#define IA32_EFER_EXECUTE_DISABLE_BIT_ENABLE_BIT 11
#define IA32_EFER_EXECUTE_DISABLE_BIT_ENABLE_FLAG 0x800
#define IA32_EFER_EXECUTE_DISABLE_BIT_ENABLE(_) (((_) >> 11) & 0x01)
        uint64_t Reserved3 : 52;
    };

    uint64_t Flags;
};

struct Fptw_t {
    uint16_t Value = 0;

    Fptw_t() = default;
    Fptw_t(const uint16_t Value) : Value(Value) {}

    static Fptw_t FromAbridged(const uint8_t Abridged) {
        uint16_t Fptw = 0;
        for (size_t BitIdx = 0; BitIdx < 8; BitIdx++) {
            const uint16_t Bits = (Abridged >> BitIdx) & 0b1;
            if (Bits == 1) {
                Fptw |= 0b00 << (BitIdx * 2);
            }
            else {
                Fptw |= 0b11 << (BitIdx * 2);
            }
        }

        return Fptw_t(Fptw);
    }

    uint8_t Abridged() const {
        uint8_t Abridged = 0;
        for (size_t Idx = 0; Idx < 8; Idx++) {
            const uint16_t Bits = (Value >> (Idx * 2)) & 0b11;
            if (Bits == 0b11) {
                Abridged |= 0b0 << Idx;
            }
            else {
                Abridged |= 0b1 << Idx;
            }
        }
        return Abridged;
    }

    bool operator==(const Fptw_t& Other) const { return Value == Other.Value; }
};



// 2816
// 2752
struct CpuState_t {
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    uint64_t Rflags;
    Seg_t Es;
    Seg_t Cs;
    Seg_t Ss;
    Seg_t Ds;
    Seg_t Fs;
    Seg_t Gs;
    Seg_t Ldtr;
    Seg_t Tr;
    GlobalSeg_t Gdtr;
    GlobalSeg_t Idtr;
    Cr0_t Cr0;
    uint64_t Cr2;
    uint64_t Cr3;
    Cr4_t Cr4;
    uint64_t Cr8;
    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint32_t Dr6;
    uint32_t Dr7;
    uint32_t Xcr0;
    Zmm_t Zmm[32];
    uint16_t Fpcw;
    uint16_t Fpsw;
    Fptw_t Fptw;
    // uint16_t Fpop;
    Float80 Fpst[8];
    uint32_t Mxcsr;
    // uint32_t MxcsrMask;
    uint64_t Tsc;
    Efer_t Efer;
    uint64_t KernelGsBase;
    uint64_t ApicBase;
    uint64_t Pat;
    uint64_t SysenterCs;
    uint64_t SysenterEip;
    uint64_t SysenterEsp;
    uint64_t Star;
    uint64_t Lstar;
    uint64_t Cstar;
    uint64_t Sfmask;
    uint64_t TscAux;
    // uint64_t CetControlU;
    // uint64_t CetControlS;
    // uint64_t Pl0Ssp;
    // uint64_t Pl1Ssp;
    // uint64_t Pl2Ssp;
    // uint64_t Pl3Ssp;
    // uint64_t InterruptSspTable;
    // uint64_t Ssp;

    CpuState_t() { memset(this, 0, sizeof(decltype(*this))); }
};

//
// _REGVAL structure reversed from dbgeng.dll
//


enum RegValType {
    REGVAL_TYPE_I32 = 0,
    REGVAL_TYPE_I16 = 2, 
    REGVAL_TYPE_I64 = 6,
    REGVAL_TYPE_FLOAT80 = 0xa,
    REGVAL_TYPE_VF128 = 0xe,
    REGVAL_TYPE_VF256,
    REGVAL_TYPE_VF512,
};

union Float128 {
    float f[4];
    std::uint8_t Bytes[16];

    Float128(const Zmm& Z) { memcpy(this, &Z, sizeof(decltype(*this))); }
};

union Float256 {
    float f[8];
    std::uint8_t Bytes[32];

    Float256(const Zmm& Z) { memcpy(this, &Z, sizeof(decltype(*this))); }
};

union Float512 {
    float f[16];
    std::uint8_t Bytes[64];
};

struct REGVAL {
    RegValType  Type;
    union {
        uint16_t I16;
        float    F32;
        uint32_t I32;
        uint64_t I64;
        double   F64;
        Float80  F80;
        Float128 VF128;
        Float256 VF256;
        Float512 VF512;
    } u;

    std::string ToString() const;
};