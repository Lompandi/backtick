
#include <regex>
#include <print>
#include <fmt/color.h>
#include <fmt/xchar.h>
#include <fmt/format.h>

#include "tui.hpp"
#include "emulator.hpp"

std::wstring StripAnsiCodes(const std::wstring& input) {
    static const std::wregex ansi_regex(L"\x1b\\[[0-9;]*[A-Za-z]");
    return std::regex_replace(input, ansi_regex, L"");
}

std::size_t VisibleLength(const std::wstring& input) {
    return StripAnsiCodes(input).length();
}

void TerminalUI::DrawUnicodeBoxToBuffer(
    std::size_t start_x,
    std::size_t start_y,
    const std::vector<std::wstring>& lines,
    std::size_t box_width,
    bool center_text
) {
    if (box_width < 4) box_width = 4;

    const wchar_t top_left = L'\u256D';
    const wchar_t top_right = L'\u256E';
    const wchar_t bottom_left = L'\u2570';
    const wchar_t bottom_right = L'\u256F';
    const wchar_t horizontal = L'\u2500';
    const wchar_t vertical = L'\u2502';

    std::size_t content_width = box_width - 2;
    std::size_t y = start_y;

    // Top border
    WriteToBuffer(start_x, y, top_left);
    for (std::size_t i = 0; i < content_width; ++i)
        WriteToBuffer(start_x + 1 + i, y, horizontal);
    WriteToBuffer(start_x + 1 + content_width, y, top_right);
    ++y;

    // Content lines
    for (const auto& line : lines) {
        std::wstring stripped = StripAnsiCodes(line);
        std::wstring content = stripped;

        if (content.length() > content_width)
            content = content.substr(0, content_width);

        std::size_t padding = content_width - content.length();
        std::size_t pad_left = center_text ? padding / 2 : 0;
        std::size_t pad_right = padding - pad_left;

        std::size_t cursor_x = start_x;

        WriteToBuffer(cursor_x++, y, vertical);
        for (std::size_t i = 0; i < pad_left; ++i)
            WriteToBuffer(cursor_x++, y, L' ');
        for (wchar_t ch : content)
            WriteToBuffer(cursor_x++, y, ch);
        for (std::size_t i = 0; i < pad_right; ++i)
            WriteToBuffer(cursor_x++, y, L' ');
        WriteToBuffer(cursor_x, y, vertical);
        ++y;
    }

    // Bottom border
    WriteToBuffer(start_x, y, bottom_left);
    for (std::size_t i = 0; i < content_width; ++i)
        WriteToBuffer(start_x + 1 + i, y, horizontal);
    WriteToBuffer(start_x + 1 + content_width, y, bottom_right);
}

void TerminalUI::DrawUnicodeBox(const std::vector<std::wstring>& lines, std::size_t box_width, bool center_text) {
    if (box_width < 4) box_width = 4;

    const wchar_t* top_left = L"\u256D";
    const wchar_t* top_right = L"\u256E";
    const wchar_t* bottom_left = L"\u2570";
    const wchar_t* bottom_right = L"\u256F";
    const wchar_t* horizontal = L"\u2500";
    const wchar_t* vertical = L"\u2502";

    std::size_t content_width = box_width - 2;

    std::wprintf(L"%ls", top_left);
    for (std::size_t i = 0; i < content_width; ++i) std::wprintf(L"%ls", horizontal);
    std::wprintf(L"%ls\n", top_right);

    for (const auto& line : lines) {
        std::wstring content = line;

        if (VisibleLength(content) > content_width) {
            content = content.substr(0, content_width);
        }

        std::size_t padding = content_width - VisibleLength(content);
        std::size_t pad_left = center_text ? padding / 2 : 0;
        std::size_t pad_right = padding - pad_left;

        std::wprintf(L"%ls%*ls%ls%*ls%ls\n",
            vertical,
            static_cast<int>(pad_left), L"",
            content.c_str(),
            static_cast<int>(pad_right), L"",
            vertical
        );
    }

    std::wprintf(L"%ls", bottom_left);
    for (std::size_t i = 0; i < content_width; ++i) std::wprintf(L"%ls", horizontal);
    std::wprintf(L"%ls\n", bottom_right);
}

std::vector<std::wstring> TerminalUI::ToWStringVector(const std::vector<std::string>& StrVec) {
    std::vector<std::wstring> result;
    result.reserve(StrVec.size());

    for (const auto& str : StrVec) {
        int wideLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        if (wideLen > 0) {
            std::wstring wstr(wideLen - 1, 0); // exclude null terminator
            MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wideLen);
            result.push_back(std::move(wstr));
        }
        else {
            result.push_back(L"[Invalid UTF-8]");
        }
    }

    return result;
}

std::wstring Reg64Diff(const std::wstring& name, std::uint64_t prev, std::uint64_t post) {
    std::wstring state = fmt::format(L"{:016x}", post);
    if (prev != post) {
        state = L"\x1b[31m" + state + L"\x1b[0m";  // Red
    }

    return fmt::format(L"{}={}", name, state);
}

void TerminalUI::FlushRenderBufferToConsole() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    //
    // Prepare emulator cpu state.
    // Set console output to UTF-8 (affects narrow I/O)
    //

    std::print("\x1b[2J\x1b[H");

    for (const auto& row : RenderBuffer_) {
        std::wstring line;
        for (auto ch : row) {
            line += static_cast<wchar_t>(ch);
        }
        DWORD written;
        WriteConsoleW(hConsole, line.c_str(), static_cast<DWORD>(line.length()), &written, nullptr);
        WriteConsoleW(hConsole, L"\n", 1, &written, nullptr);
    }

    std::fflush(stdout);
}

std::wstring ToWString(const std::string& str) {
    if (str.empty()) return std::wstring();

    int wide_len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (wide_len == 0) return std::wstring();

    std::wstring wstr(wide_len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wide_len);

    return wstr;
}

void TerminalUI::RenderFrame() {
    for (auto& row : RenderBuffer_)
        row.fill(L' ');

	const auto& InstructionBuffer = g_Debugger.Disassemble(g_Emulator.Rip(), 10);
    const auto& RegState = g_Debugger.GetDefaultRegisterState();

#define REG64_DIFF(Name, _Reg_) \
    Reg64Diff(L#Name, RegState._Reg_, PrevRegState_._Reg_)

    std::vector<std::wstring> RegContextState;
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(rax, Rax), REG64_DIFF(rbx, Rbx), REG64_DIFF(rcx, Rcx)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(rdx, Rdx), REG64_DIFF(rsi, Rsi), REG64_DIFF(rdi, Rdi)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(rip, Rip), REG64_DIFF(rsp, Rsp), REG64_DIFF(rbp, Rbp)));
    RegContextState.push_back(fmt::format(fmt::runtime(L" {}  {} {}"),
        REG64_DIFF(r8, R8), REG64_DIFF(r9, R9), REG64_DIFF(r10, R10)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(r11, R11), REG64_DIFF(r12, R12), REG64_DIFF(r13, R13)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {}"),
        REG64_DIFF(r14, R14), REG64_DIFF(r15, R15)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"cs={:04x}  ss={:04x}  ds={:04x}  es={:04x}  fs={:04x}  gs={:04x}             efl={:08x}"),
        RegState.Cs, RegState.Ss, RegState.Ds, RegState.Es, RegState.Fs, RegState.Gs, RegState.Rflags));
    
    const auto& Lines = g_Emulator.GetBreakpoints();
    std::vector<std::wstring> BreakpointInfo; 
    BreakpointInfo.reserve(Lines.size());

    for (const auto& [Id, Address] : Lines) {
        auto NameIfAvail = ToWString(g_Debugger.GetName(Address, true));

        BreakpointInfo.push_back(fmt::format(L"{}  {:016x}{}",
            Id, Address, 
            NameIfAvail.empty() ? L"" : fmt::format(L" ({})", NameIfAvail)));
    }
    
    if (Lines.size() <= 10) {
        for (int i = 0; i < 10 - Lines.size(); i++) {
            BreakpointInfo.push_back(L"");
        }
    }

    // DrawUnicodeBox(RegContextState, 92, false);
    DrawUnicodeBoxToBuffer(0, 0, RegContextState, 87, false);

    DrawUnicodeBoxToBuffer(0, 9, ToWStringVector(InstructionBuffer), 87, false);

    DrawUnicodeBoxToBuffer(88, 0, BreakpointInfo, 52, false);

    FlushRenderBufferToConsole();

    PrevRegState_ = RegState;
}