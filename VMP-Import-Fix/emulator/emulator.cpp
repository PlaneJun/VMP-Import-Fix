#include "emulator.h"

#include <filesystem>
#include <unordered_map>
#include "../ZydisWrapper/Wrapper.h"
#include "../api/api.h"
#include "../iat/iat.hpp"
#include "../utils/utils.h"

int emulator::get_mov_regIndex(uintptr_t& RegisterIndexBuffer)
{
	for (int i = 0; i < _countof(eReg64Table); i++)
	{
		if (i != 4)
		{
			if ((uc_reg_read(unicorn_, eReg64Table[i], &RegisterIndexBuffer) == UC_ERR_OK)
				&& RegisterIndexBuffer != 0 && RegisterIndexBuffer != -1)
				return i;
		}
	}

	return -1;
}

bool emulator::is_api_vaild(uintptr_t Address, api::ApiInfo& iatinfo)
{
	std::string apiName{};
	std::wstring apiModuleName{};
	uint64_t mouduleBase{};

	if(api::GetFuncName(hProc_, Address, mouduleBase,apiName, apiModuleName))
	{
		iatinfo.api_name = apiName;
		iatinfo.api_module_base = mouduleBase;
		iatinfo.api_module = std::filesystem::path(utils::wstring2stirng(apiModuleName)).filename().string();
		return true;
	}

	return false;
}

bool emulator::check_curt_emu_state(uint64_t Address)
{
	emu_num_++;
	if (emu_num_ > ExecuteInstructionMax)
	{
		printf("Time out for 0x%llx. Most likely, an invalid call.\n", curt_addr_);
		return false;
	}

	if (Address < image_base_ || Address >(image_base_ + image_size_))
	{
		printf("Instruction pointer [Out Of Range]! Start address: 0xllx\n", curt_addr_);
		return false;
	}

	return true;
}

int emulator::get_push_pop_regIndex()
{
	std::uintptr_t RegisterIndexBuffer;

	for (int i = 0; i < _countof(eReg64Table); i++)
	{
		if (i != 4)
		{
			if ((uc_reg_read(unicorn_, eReg64Table[i], &RegisterIndexBuffer) == UC_ERR_OK)
				&& RegisterIndexBuffer != 0)
				return i;
		}
	}

	return -1;
}

void emulator::trace_callback(uc_engine* Unicorn, uint64_t Address, uint32_t Size, void* UserData)
{
	int Index{};

	uint8_t InstructionBuffer[15]{};
	uintptr_t RspValue{}; 
	uintptr_t Rsp0{};
	uintptr_t Rsp4{};
	uintptr_t MovRegValue{};

	std::string sApiName{};
	iat::S_IatPatchInfo sIatPatchInfo{};
	sIatPatchInfo.m_iCallIatMode = ZydisWrapper::CALL_IAT_UNKNOWN;

	if (!check_curt_emu_state(Address))
	{
		uc_emu_stop(Unicorn);
		return;
	}

	if (uc_mem_read(Unicorn, Address, InstructionBuffer, Size) != UC_ERR_OK)
	{
		printf("failed to read address\n");
		uc_emu_stop(Unicorn);
		return;
	}

	if (uc_reg_read(Unicorn, UC_X86_REG_RSP, &RspValue) != UC_ERR_OK)
	{
		printf("failed to read Rsp address\n");
		uc_emu_stop(Unicorn);
		return;
	}

	if (uc_mem_read(Unicorn, RspValue, &Rsp0, sizeof(std::uintptr_t)) != UC_ERR_OK)
	{
		printf("failed to read Rsp content\n");
		uc_emu_stop(Unicorn);
		return;
	}

	api::ApiInfo apiInfo{};

	// ret
	if (InstructionBuffer[0] == 0xc3)
	{
		if (Rsp0 == curt_addr_ + 5 || Rsp0 == curt_addr_ + 6)
		{
			Index = get_mov_regIndex(MovRegValue);

			if (MovRegValue == 0)
				return;

			if (is_api_vaild(MovRegValue, apiInfo))
			{
				sApiName = apiInfo.api_name;

				// Update IAT patch information for MOV REG instruction.
				sIatPatchInfo.m_iCallIatMode = ZydisWrapper::CALL_IAT_MOV_REG;
				sIatPatchInfo.m_pPatchAddress = (Rsp0 == curt_addr_ + 5) ?
					curt_addr_ - (Index == 0 ? 0 : 1) :
					curt_addr_;
				sIatPatchInfo.m_iRegIndex = Index;
				sIatPatchInfo.m_pApiAddress = MovRegValue;
				sIatPatchInfo.m_pBaseModule = apiInfo.api_module_base;

				if (Rsp0 == curt_addr_ + 5)
					sIatPatchInfo.m_iIatEncryptMode = ZydisWrapper::IAT_ENCRYPT_PUSH_CALL;
				else if (Rsp0 == curt_addr_ + 6)
					sIatPatchInfo.m_iIatEncryptMode = ZydisWrapper::IAT_ENCRYPT_CALL_RET;

				printf("Call detected: 0x%llx - %s\n", curt_addr_, sApiName.c_str());
				uc_emu_stop(Unicorn);
			}
		}
		else
		{
			// If Rsp0 is export
			if (is_api_vaild(Rsp0, apiInfo))
			{
				uc_mem_read(Unicorn, RspValue + sizeof(std::uintptr_t), &Rsp4, sizeof(std::uintptr_t));
				sApiName = apiInfo.api_name;

				// @note: @colby57: Update IAT patch information for RET instruction.
				if (Rsp4 == curt_addr_ + 5) {
					sIatPatchInfo.m_iCallIatMode = ZydisWrapper::CALL_IAT_COMMON;
					sIatPatchInfo.m_iIatEncryptMode = ZydisWrapper::IAT_ENCRYPT_PUSH_CALL;
					sIatPatchInfo.m_pPatchAddress = curt_addr_ - 1;
					sIatPatchInfo.m_pApiAddress = Rsp0;
					sIatPatchInfo.m_pBaseModule = apiInfo.api_module_base;
				}
				else if (Rsp4 == curt_addr_ + 6) {
					sIatPatchInfo.m_iCallIatMode = ZydisWrapper::CALL_IAT_COMMON;
					sIatPatchInfo.m_iIatEncryptMode = ZydisWrapper::IAT_ENCRYPT_CALL_RET;
					sIatPatchInfo.m_pPatchAddress = curt_addr_;
					sIatPatchInfo.m_pApiAddress = Rsp0;
					sIatPatchInfo.m_pBaseModule = apiInfo.api_module_base;
				}

				printf("Call detected: 0x%llx - %s\n", curt_addr_, sApiName.c_str());
				uc_emu_stop(Unicorn);
			}
		}
	}
	// ret+offset
	else if (InstructionBuffer[0] == 0xC2 && InstructionBuffer[1] == sizeof(std::uintptr_t))
	{
		if (is_api_vaild(Rsp0, apiInfo))
		{
			Index = get_push_pop_regIndex();
			sApiName = apiInfo.api_name;
			sIatPatchInfo.m_iCallIatMode = ZydisWrapper::CALL_IAT_JMP;

			sIatPatchInfo.m_iIatEncryptMode = (Index != -1) ? ZydisWrapper::IAT_ENCRYPT_PUSH_CALL : ZydisWrapper::IAT_ENCRYPT_CALL_RET;
			sIatPatchInfo.m_pPatchAddress = (Index != -1) ? curt_addr_ - 1 : curt_addr_;
			sIatPatchInfo.m_pApiAddress = Rsp0;
			sIatPatchInfo.m_pBaseModule = apiInfo.api_module_base;

			printf("Call detected: 0x%llx - %s\n", curt_addr_, sApiName.c_str());
			uc_emu_stop(Unicorn);
		}
	}

	if (sIatPatchInfo.m_iCallIatMode != ZydisWrapper::CALL_IAT_UNKNOWN)
	{
		strncpy(sIatPatchInfo.m_szApi, apiInfo.api_name.c_str(), apiInfo.api_name.length());
		strncpy(sIatPatchInfo.m_szModuleName, apiInfo.api_module.c_str(), apiInfo.api_module.length());
		iat::vecPatchInfo.push_back(sIatPatchInfo);
	}
}

bool emulator::init(HANDLE hProc,void* datas, uintptr_t image_base, size_t image_size)
{
	hProc_ = hProc;
	if (uc_open(UC_ARCH_X86, UC_MODE_64, &unicorn_))
	{
		printf("uc_open failed.\n");
		return false;
	}

	image_base_ = image_base;
	image_size_ = image_size;

	if (uc_mem_map(unicorn_, image_base, image_size + 0x1000, UC_PROT_ALL))
	{
		printf("maped memory failed.\n");
		return false;
	}

	printf("mapped memory range (0x%llx-0x%llx)\n", image_base,image_base + image_size + 0x1000);

	if (uc_mem_write(unicorn_, image_base, datas, image_size))
	{
		printf("failed to write emulation code to memory\n");
		return false;
	}

	printf("stack memory range (0x%llx-0x%llx)\n", StackAddress, StackAddress + StackSize);
	stack_ = malloc(StackSize);

	if (stack_ == NULL)
	{
		printf("alloc stack memory failed.\n");
		return false;
	}

	if (uc_mem_map(unicorn_, StackAddress, StackSize, UC_PROT_ALL))
	{
		printf("[2] failed to mapping memory!\n");
		return false;
	}

	memset(stack_, StackInitValue, StackSize);

	if (uc_mem_write(unicorn_, StackAddress, stack_, StackSize))
	{
		printf("failed to write stack data to memory\n");
		return false;
	}

	std::unordered_map<uc_x86_reg, uintptr_t> unMapRegisters =
	{
		{UC_X86_REG_RSP, StackAddress + StackSize - sizeof(uintptr_t) * 100},
		{UC_X86_REG_RAX, 0x0},
		{UC_X86_REG_RBX, 0x0},
		{UC_X86_REG_RCX, 0x0},
		{UC_X86_REG_RDX, 0x0},
		{UC_X86_REG_RBP, 0x0},
		{UC_X86_REG_RSI, 0x0},
		{UC_X86_REG_RDI, 0x0},
		{UC_X86_REG_R8, 0x0},
		{UC_X86_REG_R9, 0x0},
		{UC_X86_REG_R10, 0x0},
		{UC_X86_REG_R11, 0x0},
		{UC_X86_REG_R12, 0x0},
		{UC_X86_REG_R13, 0x0},
		{UC_X86_REG_R14, 0x0},
		{UC_X86_REG_R15, 0x0},
	};

	for (const auto& [Register, InitialValue] : unMapRegisters)
	{
		if (uc_reg_write(unicorn_, Register, (void*)&InitialValue) != UC_ERR_OK)
		{
			printf("Failed to initialize register %d\n", Register);
			return false;
		}
	}

	if (uc_context_alloc(unicorn_, &unicorn_ctx_))
	{
		printf("Failed on uc_context_alloc()\n");
		return false;
	}

	if (uc_context_save(unicorn_, unicorn_ctx_))
	{
		printf("Failed on uc_context_save()\n");
		return false;
	}

	if (uc_hook_add(unicorn_, &unicorn_hook_trace_, UC_HOOK_CODE, trace_callback, NULL, 1, 0) != UC_ERR_OK)
	{
		printf("Failed on uc_hook_add()\n");
		return 0;
	}

	return true;
}

void emulator::start(uintptr_t address)
{
	emu_num_ = 0;

	if (uc_context_restore(unicorn_, unicorn_ctx_))
	{
		printf("failed on uc_context_restore()\n");
		return;
	}

	if (uc_mem_write(unicorn_, StackAddress, stack_, StackSize))
	{
		printf("failed to write stack data to memory\n");
		return;
	}

	uc_emu_start(unicorn_, address, image_base_ + image_size_ - 1, 0, 0);
}
