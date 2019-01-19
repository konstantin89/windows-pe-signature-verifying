#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "./../src/PeSignatureVerifier.h"

#pragma region VerifySignature Tests
TEST_CASE("Test common Windows system files", "[windows]")
{

	bool lResult = PeSignatureVerifier::IsSignatureVerified(
		L"C:\\Windows\\explorer.exe");

	REQUIRE(lResult == true);

	lResult = PeSignatureVerifier::IsSignatureVerified(
		L"C:\\Windows\\System32\\msi.dll");

	REQUIRE(lResult == true);

	lResult = PeSignatureVerifier::IsSignatureVerified(
		L"C:\\Windows\\System32\\Defrag.exe");

	REQUIRE(lResult == true);

	lResult = PeSignatureVerifier::IsSignatureVerified(
		L"C:\\Windows\\System32\\calc.exe");

	REQUIRE(lResult == true);
}

TEST_CASE("Try to check if current running exe is signed", "[GetModuleFileName]")
{
	wchar_t lCurrentExePath[MAX_PATH];
	GetModuleFileName(NULL, lCurrentExePath, MAX_PATH);

	bool lResult = PeSignatureVerifier::IsSignatureVerified(lCurrentExePath);

	REQUIRE(lResult == false);
}

TEST_CASE("Try to scan file with invalid name", "[invalid]")
{
	bool lResult = PeSignatureVerifier::IsSignatureVerified(L"INVALID_FILE_NAME");

	REQUIRE(lResult == false);
}
#pragma endregion

#pragma region GetSignatureStatus Tests
TEST_CASE("GetSignatureStatus:Test common Windows system files", "[windows]")
{

	DWORD lResult = PeSignatureVerifier::GetSignatureStatus(
		L"C:\\Windows\\explorer.exe");

	REQUIRE(lResult == ERROR_SUCCESS);

	lResult = PeSignatureVerifier::GetSignatureStatus(
		L"C:\\Windows\\System32\\msi.dll");

	REQUIRE(lResult == ERROR_SUCCESS);

	lResult = PeSignatureVerifier::GetSignatureStatus(
		L"C:\\Windows\\System32\\Defrag.exe");

	REQUIRE(lResult == ERROR_SUCCESS);

	lResult = PeSignatureVerifier::GetSignatureStatus(
		L"C:\\Windows\\System32\\calc.exe");

	REQUIRE(lResult == ERROR_SUCCESS);
}

TEST_CASE("GetSignatureStatus:Try to check if current running exe is signed", "[GetModuleFileName]")
{
	wchar_t lCurrentExePath[MAX_PATH];
	GetModuleFileName(NULL, lCurrentExePath, MAX_PATH);

	DWORD lResult = PeSignatureVerifier::GetSignatureStatus(lCurrentExePath);
	printf("result: %d\n",lResult);

	REQUIRE(lResult != ERROR_SUCCESS);
}

TEST_CASE("GetSignatureStatus:Try to scan file with invalid name", "[invalid]")
{
	DWORD lResult = PeSignatureVerifier::GetSignatureStatus(L"INVALID_FILE_NAME");
	printf("result: %d\n", lResult);

	REQUIRE(lResult != ERROR_SUCCESS);
}
#pragma endregion