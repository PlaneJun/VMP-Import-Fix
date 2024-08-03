#pragma once
#include <string>
#include <stdint.h>

namespace  utils
{
	struct ParsedURL {
		std::string scheme;
		std::string host;
		std::string port;
		std::string path;
		std::string query;
	};

	uint64_t hex2dec(std::string hex);

	// 12 -> C
	std::string dec2hex(uint64_t dec);

	// 12 -> 0000000C
	std::string dec2hex2(uint64_t dec);

	std::string utf2gbk(const char* utf8);

	std::string gbk2utf8(std::string gbkStr);

	std::string wstring2stirng(std::wstring wstr);

	std::wstring string2wstirng(std::string str);

	std::string get_filename_from_addr(uint64_t addr);

	// out:12 34 56 78 91
	std::string bytesToHexString(const uint8_t* bytes, const int length);

	// out:1234567891
	std::string bytesToHexString2(const uint8_t* bytes, const int length);
}
