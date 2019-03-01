#include "./../catch.hpp"
#include "./../src/PeSignatureVerifier.h"

#define WINDOWS_EXPLORER_PE_WSTR L"C:\\Windows\\explorer.exe"

TEST_CASE("Ensure that explorer.exe is trusted PE", "[windows]")
{
	auto lResult = PeSignatureVerifier::CheckFileSignature(
		WINDOWS_EXPLORER_PE_WSTR);

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

TEST_CASE("Try to get certificate info for signed explorer.exe", "[exproler]")
{

	PeSignatureVerifier::SignerInfoPtr lSignerInfo;

	auto lResult = PeSignatureVerifier::GetCertificateInfo(WINDOWS_EXPLORER_PE_WSTR, lSignerInfo);

	REQUIRE(lResult == ERROR_SUCCESS);

	REQUIRE(lSignerInfo->issuerName.empty() == false);
	REQUIRE(lSignerInfo->serialNumber.empty() == false);
	REQUIRE(lSignerInfo->signAlgorithm.empty() == false);
	REQUIRE(lSignerInfo->subjectName.empty() == false);
}

TEST_CASE("Try to get time stamp certificate info for signed explorer.exe", "[exproler]")
{
	/*

	PeSignatureVerifier::TimeStampCertInfoPtr lSignerInfo;

	auto lResult = PeSignatureVerifier::GetTimestampCertificateInfo(WINDOWS_EXPLORER_PE_WSTR, lSignerInfo);

	REQUIRE(lResult == ERROR_SUCCESS);

	REQUIRE(lSignerInfo->issuerName.empty() == false);
	REQUIRE(lSignerInfo->serialNumber.empty() == false);
	REQUIRE(lSignerInfo->signAlgorithm.empty() == false);
	REQUIRE(lSignerInfo->subjectName.empty() == false);
	REQUIRE(lSignerInfo->GetDateAsWstr().empty() == false);

	*/
}