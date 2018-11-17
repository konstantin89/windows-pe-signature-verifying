#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "./../src/PeSignatureVerifier.h"

TEST_CASE("Test common Windows system files", "[windows]")
{

	bool lResult = PeSignatureVerifier::VerifySignature(
		L"C:\\Windows\\explorer.exe");

	REQUIRE(lResult == true);

	lResult = PeSignatureVerifier::VerifySignature(
		L"C:\\Windows\\System32\\msi.dll");

	REQUIRE(lResult == true);

	lResult = PeSignatureVerifier::VerifySignature(
		L"C:\\Windows\\System32\\Defrag.exe");

	REQUIRE(lResult == true);

	lResult = PeSignatureVerifier::VerifySignature(
		L"C:\\Windows\\System32\\calc.exe");

	REQUIRE(lResult == true);
}

TEST_CASE("Test common Program Files applications", "[ProgramFiles]")
{

	bool lResult = PeSignatureVerifier::VerifySignature(
		L"C:\\Program Files\\Mozilla Firefox\\firefox.exe");

	REQUIRE(lResult == true);

}

TEST_CASE("Try to check if current running exe is signed", "[GetModuleFileName]")
{
	wchar_t lCurrentExePath[MAX_PATH];
	GetModuleFileName(NULL, lCurrentExePath, MAX_PATH);

	bool lResult = PeSignatureVerifier::VerifySignature(lCurrentExePath);

	REQUIRE(lResult == false);
}

TEST_CASE("Try to scan file with invalid name", "[invalid]")
{
	bool lResult = PeSignatureVerifier::VerifySignature(L"INVALID_FILE_NAME");

	REQUIRE(lResult == false);
}