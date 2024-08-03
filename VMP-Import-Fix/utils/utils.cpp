#include "utils.h"
#include <sstream>
#include <filesystem>
#include <windows.h>

#pragma comment(lib,"Version.lib")

unsigned char ToHex(unsigned char x)
{
	return  x > 9 ? x + 55 : x + 48;
}

unsigned char FromHex(unsigned char x)
{
	unsigned char y;
	if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;
	else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;
	else if (x >= '0' && x <= '9') y = x - '0';
	else return 0;
	return y;
}

namespace  utils
{

	uint64_t hex2dec(std::string hex)
	{
		std::stringstream ss2;
		uint64_t d2;
		ss2 << std::hex << hex; //选用十六进制输出
		ss2 >> d2;
		return d2;
	}

	// 12 -> C
	std::string dec2hex(uint64_t dec)
	{
		std::stringstream ss2;
		ss2 << std::hex << dec;
		return ss2.str();
	}

	// 12 -> 0000000C
	std::string dex2hex2(uint64_t dec)
	{
		char buffer[100]{};
		sprintf_s(buffer, "%p", dec);
		return buffer;
	}


	std::string utf2gbk(const char* utf8)
	{
		int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
		wchar_t* wstr = new wchar_t[len + 1];
		memset(wstr, 0, len + 1);
		MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wstr, len);
		len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
		char* str = new char[len + 1];
		memset(str, 0, len + 1);
		WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL);
		if (wstr) delete[] wstr;
		return str;
	}


	std::string gbk2utf8(std::string gbkStr)
	{
		std::string outUtf8 = "";
		int n = MultiByteToWideChar(CP_ACP, 0, gbkStr.c_str(), -1, NULL, 0);
		WCHAR* str1 = new WCHAR[n];
		MultiByteToWideChar(CP_ACP, 0, gbkStr.c_str(), -1, str1, n);
		n = WideCharToMultiByte(CP_UTF8, 0, str1, -1, NULL, 0, NULL, NULL);
		char* str2 = new char[n];
		WideCharToMultiByte(CP_UTF8, 0, str1, -1, str2, n, NULL, NULL);
		outUtf8 = str2;
		delete[]str1;
		str1 = NULL;
		delete[]str2;
		str2 = NULL;
		return outUtf8;
	}

	std::string wstring2stirng(std::wstring wstr)
	{
		std::string result;
		//获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
		int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
		char* buffer = new char[len + 1];
		//宽字节编码转换成多字节编码  
		WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
		buffer[len] = '\0';
		//删除缓冲区并返回值  
		result.append(buffer);
		delete[] buffer;
		return result;
	}

	std::wstring string2wstirng(std::string str)
	{
		std::wstring result;
		//获取缓冲区大小，并申请空间，缓冲区大小按字符计算  
		int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), NULL, 0);
		TCHAR* buffer = new TCHAR[len + 1];
		//多字节编码转换成宽字节编码  
		MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer, len);
		buffer[len] = '\0';             //添加字符串结尾  
		result.append(buffer);
		delete[] buffer;
		return result;
	}

	std::string get_filename_from_addr(uint64_t addr)
	{
		HMODULE moduleHandle;
		DWORD moduleSize;
		if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(addr), &moduleHandle))
		{
			char modulePath[MAX_PATH];
			if (GetModuleFileNameA(moduleHandle, modulePath, MAX_PATH))
			{
				return modulePath;
			}
		}

		return std::string();
	}

	std::string bytesToHexString(const BYTE* bytes, const int length)
	{
		if (bytes == NULL) {
			return "";
		}
		std::string buff;
		const int len = length;
		for (int j = 0; j < len; j++) {
			int high = bytes[j] / 16, low = bytes[j] % 16;
			buff += (high < 10) ? ('0' + high) : ('a' + high - 10);
			buff += (low < 10) ? ('0' + low) : ('a' + low - 10);
			buff += " ";
		}
		return buff;
	}

	std::string bytesToHexString2(const uint8_t* bytes, const int length)
	{
		if (bytes == NULL) {
			return "";
		}
		std::string buff;
		const int len = length;
		for (int j = 0; j < len; j++) {
			int high = bytes[j] / 16, low = bytes[j] % 16;
			buff += (high < 10) ? ('0' + high) : ('a' + high - 10);
			buff += (low < 10) ? ('0' + low) : ('a' + low - 10);
		}
		return buff;
	}

}
