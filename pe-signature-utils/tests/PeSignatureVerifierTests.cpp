#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "./../src/PeSignatureVerifier.h"

TEST_CASE("Test common Windows system files", "[windows]")
{

	auto lResult = PeSignatureVerifier::CheckFileSignature(
		L"C:\\Windows\\explorer.exe");

	REQUIRE(lResult == ERROR_SUCCESS);

	lResult = PeSignatureVerifier::CheckFileSignature(
		L"C:\\Windows\\System32\\msi.dll");

	REQUIRE(lResult == ERROR_SUCCESS);

	lResult = PeSignatureVerifier::CheckFileSignature(
		L"C:\\Windows\\System32\\Defrag.exe");

	REQUIRE(lResult == ERROR_SUCCESS);

	lResult = PeSignatureVerifier::CheckFileSignature(
		L"C:\\Windows\\System32\\calc.exe");

	REQUIRE(lResult == ERROR_SUCCESS);
}

TEST_CASE("Try to check if current running exe is signed", "[GetModuleFileName]")
{
	wchar_t lCurrentExePath[MAX_PATH];
	GetModuleFileName(NULL, lCurrentExePath, MAX_PATH);

	bool lResult = PeSignatureVerifier::CheckFileSignature(lCurrentExePath);

	REQUIRE(lResult != ERROR_SUCCESS);
}

TEST_CASE("Try to scan file with invalid name", "[invalid]")
{
	auto lResult = PeSignatureVerifier::CheckFileSignature(L"INVALID_FILE_NAME");

	REQUIRE(lResult != ERROR_SUCCESS);
}
