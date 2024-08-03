// VMP-Import-Fix.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>
#include <stdint.h>
#include "argparse.hpp"
#include "utils/utils.h"
#include "process/process.h"
#include "pefile/pefile.h"
#include "ZydisWrapper/Wrapper.h"
#include "emulator/emulator.h"
#include "iat/iat.hpp"

double calcEntropy(std::vector<uint8_t> bytes)
{
	double Entropy{};
	std::map<std::uint8_t, double> mapByteProbabilities;
	std::map<std::uint8_t, int> mapByteFrequencies;

	for (const auto& byte : bytes)
		mapByteFrequencies[byte]++;

	for (const auto& pair : mapByteFrequencies)
		mapByteProbabilities[pair.first] = static_cast<double>(pair.second) / bytes.size();

	for (const auto& pair : mapByteProbabilities)
		Entropy -= pair.second * log2(pair.second);

	return Entropy;
}

int main(int argc, char** argv)
{
	argparse::ArgumentParser Argv("VMP-Import-Fix");

	Argv.add_argument("-p", "--pid")
		.help("process pid")
		.required()
		.scan<'d', int>();

	Argv.add_argument("-m", "--module")
		.help("module name,Default use process base.")
		.default_value<std::string>("");

	Argv.add_argument("-a", "--addr")
		.help("module base,use hex with prefix,eg:0x1234")
		.default_value<std::string>("0x0");

	Argv.add_argument("-l", "--len")
		.help("module len,use hex with prefix,eg:0x1234")
		.default_value<std::string>("0x0");

	Argv.add_argument("-d", "--dump")
		.help("fix iat & dump to file")
		.default_value(false)
		.implicit_value(true)
		.nargs(0);

	Argv.add_argument("-o", "--oep")
		.help("if need dump,plz input oep with prefix,eg:0x1234")
		.default_value<std::string>("0x0");
		

	try
	{
		Argv.parse_args(argc, argv);
	}
	catch (const std::runtime_error& err)
	{
		std::cerr << err.what() << std::endl;
		std::cerr << Argv;
		std::exit(1);
	}

	// parse argv
	auto process_id = Argv.get<int>("--pid");
	auto module_name = Argv.get<std::string>("--module");
	auto module_base = utils::hex2dec(Argv.get<std::string>("--addr"));
	auto module_size = utils::hex2dec(Argv.get<std::string>("--len"));
	auto bDump = Argv.get<bool>("--dump");
	auto rva_oep = utils::hex2dec(Argv.get<std::string>("--oep"));

	Process proc;
	if(!proc.open_process(process_id))
	{
		printf("open process failed.\n");
	}

	if(proc.isWow64())
	{
		printf("not support 32 bit.\n");
		return 0;
	}

	PEFile pe_{};
	bool status = false;;
	if(module_base > 0 && module_size > 0)
	{
		std::vector<uint8_t> buffer(module_size);
		if(!proc.read_mem_force(module_base, module_size, buffer.data()))
		{
			printf("read %p,0x%lx failed.\n", module_base, module_size);
			return 0;
		}
		status = pe_.load_from_memory(buffer.data(), buffer.size());
	}
	else
	{
		if(module_name.empty())
		{
			module_name = Process::get_name_by_pid(process_id);
		}
		status = pe_.load_from_process(process_id, utils::string2wstirng(module_name).c_str());
		if(status)
		{
			module_base = proc.get_module_handle_by_name(process_id, utils::string2wstirng(module_name).c_str());
			module_size = pe_.get_size_of_image();
		}
	}

	if(!status)
	{
		printf("load pe failed!\n");
		return 0;
	}

	// find vmp section
	std::vector<std::string> vmpSections{};
	for(const auto& sec : pe_.get_section_headers())
	{
		if(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			std::vector<std::uint8_t> vecBuffer(sec->Misc.VirtualSize);
			memcpy(vecBuffer.data(),pe_.get_data()+sec->VirtualAddress,vecBuffer.size());
			auto Entropy = calcEntropy(vecBuffer);
			if (Entropy > 7.0)
			{
				printf("[vmp section]\n");
				vmpSections.emplace_back(std::string((char*)sec->Name));
			}
			printf("SecName = %s\nEntropy = %lf\n", std::string((char*)sec->Name).c_str(), Entropy);
			printf("\n");
		}
	}

	// find encrypt-iat
	std::vector<uintptr_t> vmpImports;
	for (const auto& sec : pe_.get_section_headers())
	{
		if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			std::find(vmpSections.begin(), vmpSections.end(), (char*)sec->Name) == vmpSections.end())
		{
			// search all maby is call instruction.
			uint64_t start = module_base + sec->VirtualAddress;
			uint64_t end = start + sec->Misc.VirtualSize;
			auto vecResults = proc.find_pattern("E8 ?? ?? ?? ??", start, end);

			// filter out only in vmp range
			S_DisasmWrapper sDisasm{};
			for (const auto& tmp : vecResults)
			{
				uint64_t offset = tmp - module_base;
				uintptr_t addr = reinterpret_cast<uintptr_t>(&pe_.get_data()[offset]);

				sDisasm.m_pRuntimeAddr = tmp;
				if (*(unsigned char*)addr == 0xE8 && ZydisWrapper::Disasm(sDisasm, addr, 5))
				{
					// Calculate the absolute address using the disassembled instruction.
					uintptr_t pCalculatedAddress = ZydisWrapper::CalculateAbsoluteAddr(sDisasm, 0);
					if(!pCalculatedAddress)
						continue;

					// Skip addresses that are outside the image range.
					if (pCalculatedAddress > (module_base + module_size) || pCalculatedAddress < module_base)
						continue;

					// Skip addresses within the specified section range.
					if (pCalculatedAddress >= (module_base + sec->VirtualAddress) &&
						pCalculatedAddress <= (module_base + sec->VirtualAddress + sec->Misc.VirtualSize))
						continue;

					vmpImports.emplace_back(tmp);
				}
			}
		}
	}


	// init unicorn
	const auto emu_status = emulator::init(proc.get_handle(), pe_.get_data(), module_base, module_size);
	if (!emu_status)
	{
		printf("Cannot initialize emulator.\n");
		return 0;
	}

	// decrypt-iat address
	for (auto addr : vmpImports)
	{
		emulator::curt_addr_ = addr;
		emulator::start(addr);
	}

	// build iat table & patch
	uint64_t lpImportTable = proc.alloc_mem_nearby(module_base,iat::vecPatchInfo.size()*8+8);
	for(int i=0;i< iat::vecPatchInfo.size();i++)
	{
		auto& iatInfo = iat::vecPatchInfo[i];
		iatInfo.m_pIatAddress = lpImportTable + i * 8;
		proc.write<uintptr_t>(iatInfo.m_pIatAddress, iatInfo.m_pApiAddress);

		const auto iat_mode = iatInfo.m_iCallIatMode;
		if (iat_mode != ZydisWrapper::CALL_IAT_UNKNOWN)
		{
			// Assemble the call instruction.
			std::vector<std::uint8_t> vecCode(32);
			size_t code_len = ZydisWrapper::AssembleCall(vecCode.data(), vecCode.size(), iat_mode, iatInfo.m_pIatAddress, iatInfo.m_pPatchAddress, iatInfo.m_iRegIndex);
			if (code_len > 0)
			{
				// @note: @colby57: Check if the assembled code is valid.
				if (code_len == 5 || code_len == 6)
				{
					if (iat_mode == ZydisWrapper::CALL_IAT_COMMON)
					{
						if (code_len == 5)
						{
							// e8 ? ? ? ?
							iatInfo.m_offset_reloc = 1;
						}
						else
						{
							// ff 15 ? ? ? ?
							iatInfo.m_offset_reloc = 2;
						}
					}
					else if (iat_mode == ZydisWrapper::CALL_IAT_MOV_REG)
					{
						// 48 x x ? ? ? ?
						iatInfo.m_offset_reloc = 3;
					}
					else if (iat_mode == ZydisWrapper::CALL_IAT_JMP)
					{
						// ff 15 ? ? ? ?
						iatInfo.m_offset_reloc = 2;
					}

					// write opcode to process patch addr
					if(!proc.write_mem(iatInfo.m_pPatchAddress, code_len, reinterpret_cast<uintptr_t>(vecCode.data())))
					{
						printf("error patch to: 0x%llx", iatInfo.m_pPatchAddress);
					}

				}
			}
			else
			{
				printf("failed to asm call from patch address: 0x%llx", iatInfo.m_pPatchAddress);
			}
		}
	}
	printf("lpImportTable = 0x%llx\n", lpImportTable);

	if(bDump)
	{
		std::vector<uint8_t> new_buffer(module_size);
		if(!proc.read_mem_force(module_base, module_size, new_buffer.data()))
		{
			printf("read new buffer faild!\n");
			return 0;
		}

		PEFile dump_pe{};
		if(!dump_pe.load_from_memory(new_buffer.data(), new_buffer.size()))
		{
			printf("dump_pe load failed!\n");
			return 0;
		}

		std::map<std::string, std::map<std::string, std::vector<uint64_t>>> AddedImports;
		for (const auto& sIatPatchInfo : iat::vecPatchInfo)
		{
			AddedImports[sIatPatchInfo.m_szModuleName][sIatPatchInfo.m_szApi].push_back(sIatPatchInfo.m_pPatchAddress + sIatPatchInfo.m_offset_reloc - module_base);
		}

		std::string dump_name = proc.get_modulename_by_handle(module_base);
		dump_pe.add_iat_section(module_base, rva_oep, AddedImports);
		dump_pe.write_to_file(dump_name.append(".fix"));
		printf("dump file at:%s\n", dump_name.c_str());
	}

	return 0;
}

