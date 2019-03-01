#include "./../../catch.hpp"
#include "native_api_wrappers/HashApiWrapper.h"

#define CORRECT_SHA256_HASH_LENGTH 64

#include <iostream>

TEST_CASE("Calculate sha256 for explorer", "[windows, explorer]")
{
	std::wstring lSha256Wstr;
	std::wstring lExplorerPath = L"c:\\windows\\explorer.exe";

	auto lRetVal = HashApiWrapper::CalculateFileHash(
		lExplorerPath,
		L"SHA256",
		lSha256Wstr);

	REQUIRE(lRetVal == ERROR_SUCCESS);
	REQUIRE(lSha256Wstr.length() == CORRECT_SHA256_HASH_LENGTH);
}

TEST_CASE("Error case - invalid file name", "[error]")
{
	std::wstring lSha256Wstr;
	std::wstring lExplorerPath = L"f:\\invalid.sys";

	auto lRetVal = HashApiWrapper::CalculateFileHash(
		lExplorerPath,
		L"SHA256",
		lSha256Wstr);

	REQUIRE(lRetVal == ERROR_PATH_NOT_FOUND);
	REQUIRE(lSha256Wstr.empty() == true);
}

TEST_CASE("Error case - invalid hash algorithm", "[error]")
{
	std::wstring lSha256Wstr;
	std::wstring lExplorerPath = L"c:\\windows\\explorer.exe";

	auto lRetVal = HashApiWrapper::CalculateFileHash(
		lExplorerPath,
		L"SHA666",
		lSha256Wstr);

	REQUIRE(lRetVal == NTE_BAD_ALGID);
	REQUIRE(lSha256Wstr.empty() == true);
}

TEST_CASE("Test ByteHashIntoWstring - One byte hash", "[ByteHashIntoWstring]")
{
	const size_t lBytesCount = 1;
	BYTE lByte[lBytesCount] = {0xab};

	std::wstring lWstr = HashApiWrapper::ByteHashIntoWstring(lByte, lBytesCount);

	REQUIRE(lWstr == L"AB");
}

TEST_CASE("Test ByteHashIntoWstring - NULL hash", "[ByteHashIntoWstring]")
{
	std::wstring lWstr = HashApiWrapper::ByteHashIntoWstring(NULL, 0);

	REQUIRE(lWstr == L"");
}

TEST_CASE("Test ByteHashIntoWstring - hash of all hex characters", "[ByteHashIntoWstring]")
{
	const size_t lBytesCount = 8;
	BYTE lByte[lBytesCount] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

	std::wstring lWstr = HashApiWrapper::ByteHashIntoWstring(lByte, lBytesCount);
	
	REQUIRE(lWstr == L"0123456789ABCDEF");
}
