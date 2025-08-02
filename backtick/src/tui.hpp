#pragma once

#include <array>
#include <vector>

#include "debugger.hpp"

class TerminalUI {
public:
	TerminalUI() { SetConsoleOutputCP(CP_UTF8); }

	void RenderFrame();
	
	void WriteToBuffer(std::size_t x, std::size_t y, wchar_t ch) {
		RenderBuffer_[y][x] = ch;
	}

	void DrawUnicodeBox(const std::vector<std::wstring>& lines, std::size_t box_width = 72, bool center_text = false);

	void DrawUnicodeBoxToBuffer(
		std::size_t start_x,
		std::size_t start_y,
		const std::vector<std::wstring>& lines,
		std::size_t box_width,
		bool center_text
	);

	void FlushRenderBufferToConsole();

	std::vector<std::wstring> ToWStringVector(const std::vector<std::string>& StrVec);

private:
	// [y][x]
	std::array<std::array<uint16_t, 140>, 40> RenderBuffer_;
	DefaultRegistersState PrevRegState_;
};