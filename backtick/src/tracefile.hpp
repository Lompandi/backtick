#pragma once

#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

struct Checkpoint_t;

class TraceFileStream {
public:
	TraceFileStream() = default;

	void SetFilePath(const std::string& Path) { FilePath_ = Path; }

	std::string GetFilePath() const { return FilePath_; }

	bool WriteTraceToFileIfNeeded(const std::deque<Checkpoint_t>& DataToWrite);

	std::deque<Checkpoint_t> ReadTraceFromFile();

private:
	std::ofstream OutputFile_;
	std::ifstream InputFile_;

	std::string FilePath_;
};