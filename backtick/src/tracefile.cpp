
#include "emulator.hpp"
#include "tracefile.hpp"

struct CpuStateDeltaElem_t {
	std::uint64_t Offset;
	std::uint64_t Value;
};

struct DirtiedMemDataElem_t {
	std::uint64_t Address;
	std::uint64_t Size;
};


bool TraceFileStream::WriteTraceToFileIfNeeded(const std::deque<Checkpoint_t>& DataToWrite) {
	//
	// Dont need to write to file
	//
	if (DataToWrite.size() <= 500'000) {
		return true;
	}

	OutputFile_.open(FilePath_, std::ios::binary);
	if (!OutputFile_.is_open()) {
		return false;
	}

	std::vector<std::uint8_t> TraceBuffer;

	// Reverse iterate so most recent checkpoint comes first
	for (auto it = DataToWrite.rbegin(); it != DataToWrite.rend(); ++it) {
		const auto& Cp = *it;

		std::uint64_t CpuStateDeltaCount = Cp.CpuStateDelta_.size();
		TraceBuffer.insert(TraceBuffer.end(),
			reinterpret_cast<std::uint8_t*>(&CpuStateDeltaCount),
			reinterpret_cast<std::uint8_t*>(&CpuStateDeltaCount) + sizeof(std::uint64_t));

		for (const auto& [Offset, Value] : Cp.CpuStateDelta_) {
			CpuStateDeltaElem_t DeltaElem{ Offset, Value };
			TraceBuffer.insert(TraceBuffer.end(),
				reinterpret_cast<std::uint8_t*>(&DeltaElem),
				reinterpret_cast<std::uint8_t*>(&DeltaElem) + sizeof(DeltaElem));
		}

		std::uint64_t DirtiedBytesCount = Cp.DirtiedBytes_.size();
		TraceBuffer.insert(TraceBuffer.end(),
			reinterpret_cast<std::uint8_t*>(&DirtiedBytesCount),
			reinterpret_cast<std::uint8_t*>(&DirtiedBytesCount) + sizeof(std::uint64_t));

		for (const auto& [Address, OriginalData] : Cp.DirtiedBytes_) {
			DirtiedMemDataElem_t DirtiedElem{
				.Address = Address,
				.Size = OriginalData.size()
			};
			TraceBuffer.insert(TraceBuffer.end(),
				reinterpret_cast<std::uint8_t*>(&DirtiedElem),
				reinterpret_cast<std::uint8_t*>(&DirtiedElem) + sizeof(DirtiedElem));

			TraceBuffer.insert(TraceBuffer.end(),
				OriginalData.begin(), OriginalData.end());
		}
	}

	OutputFile_.write(reinterpret_cast<char*>(TraceBuffer.data()), TraceBuffer.size());
	bool Success = OutputFile_.good();
	OutputFile_.close();
	return Success;
}

std::deque<Checkpoint_t> TraceFileStream::ReadTraceFromFile() {
	std::deque<Checkpoint_t> Checkpoints;

	InputFile_.open(FilePath_, std::ios::binary | std::ios::in);
	if (!InputFile_.is_open()) {
		return {};
	}

	InputFile_.seekg(0, std::ios::beg);

	while (InputFile_) {
		Checkpoint_t Cp;

		std::uint64_t CpuDeltaCount = 0;
		if (!InputFile_.read(reinterpret_cast<char*>(&CpuDeltaCount), sizeof(CpuDeltaCount))) break;

		for (std::uint64_t i = 0; i < CpuDeltaCount; ++i) {
			CpuStateDeltaElem_t DeltaElem;
			InputFile_.read(reinterpret_cast<char*>(&DeltaElem), sizeof(DeltaElem));
			Cp.CpuStateDelta_[DeltaElem.Offset] = DeltaElem.Value;
		}

		std::uint64_t DirtiedCount = 0;
		InputFile_.read(reinterpret_cast<char*>(&DirtiedCount), sizeof(DirtiedCount));

		for (std::uint64_t i = 0; i < DirtiedCount; ++i) {
			DirtiedMemDataElem_t DirtiedElem;
			InputFile_.read(reinterpret_cast<char*>(&DirtiedElem), sizeof(DirtiedElem));

			std::vector<std::uint8_t> OriginalData(DirtiedElem.Size);
			InputFile_.read(reinterpret_cast<char*>(OriginalData.data()), DirtiedElem.Size);

			Cp.DirtiedBytes_[DirtiedElem.Address] = std::move(OriginalData);
		}

		Checkpoints.push_back(std::move(Cp));
	}

	InputFile_.close();
	return Checkpoints;
}