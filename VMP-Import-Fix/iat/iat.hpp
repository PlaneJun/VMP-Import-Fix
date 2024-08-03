#pragma once
#include <vector>
#include <stdint.h>

namespace iat
{
	struct S_IatPatchInfo
	{
		int m_iCallIatMode{};
		int m_iIatEncryptMode{};
		int m_iRegIndex{};

		uintptr_t m_pPatchAddress{};
		uintptr_t m_pBaseModule{};
		uintptr_t m_pApiAddress{};
		uintptr_t m_pIatAddress{};

		char m_szModuleName[256] = {0};
		char m_szApi[256] = { 0 };

		int m_offset_reloc;
	};

	inline std::vector<S_IatPatchInfo> vecPatchInfo{};
}
