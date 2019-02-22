
#include <iostream>

#include "PeSignatureVerifier.h"


DWORD CheckFile(std::wstring aFileName)
{

	DWORD lRetVal = ERROR_SUCCESS;
	PeSignatureVerifier::SignerInfoPtr lCertInfo;
	PeSignatureVerifier::TimeStampCertInfoPtr lTsCertInfo;

	std::wstring lSha256Wstr;
	lRetVal = PeSignatureVerifier::CalculateFileHash(
		aFileName,
		L"SHA256",
		lSha256Wstr);

	lRetVal = PeSignatureVerifier::CheckFileSignature(aFileName);

	std::wcout << L"File name: " << aFileName.c_str() << std::endl;
	if (lRetVal == ERROR_SUCCESS)
	{
		std::wcout << L"Verified: " << L"Signed" << std::endl;
	}
	else
	{
		std::wcout << L"Verified: " << L"Unsigned" << std::endl;
	}
	
	std::wcout << L"SHA256: " << lSha256Wstr.c_str() << std::endl;

	lRetVal = PeSignatureVerifier::GetCertificateInfo(aFileName, lCertInfo);

	if (lRetVal == ERROR_SUCCESS)
	{	
		std::wcout << "Signer Info" << std::endl;
		lCertInfo->PrintCertificateInfo();
	}

	lRetVal = PeSignatureVerifier::GetTimestampCertificateInfo(aFileName, lTsCertInfo);

	if (lRetVal == ERROR_SUCCESS)
	{
		std::wcout << "Time stamp certificate info" << std::endl;
		lTsCertInfo->PrintCertificateInfo();
	}

	return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t* argv[])
{

	if (argc < 2)
	{
		//return 1;
	}

	std::wstring lFilePath(argv[1]);

	auto lRetVal = CheckFile(L"C:\\Program Files\\Mozilla Firefox\\firefox.exe");

	lRetVal = CheckFile(lFilePath);

	return lRetVal;
}
