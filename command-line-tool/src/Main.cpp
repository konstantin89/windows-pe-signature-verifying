
#include <iostream>

#include "CryptoApiWrapper.h"
#include "PeSignatureVerifier.h"


#define PRINT_LINE() std::cout << "-----------------------------------------" << std::endl

int main()
{
	std::wstring lFileNameWstr(L"C:\\Program Files\\Mozilla Firefox\\firefox.exe");
	std::shared_ptr<SignerInfo> lCertInfo;

	DWORD lRetVal = CryptoApiWrapper::GetCertificateInfo(
		lFileNameWstr,
		lCertInfo);

	if (lRetVal == ERROR_SUCCESS)
	{
		lCertInfo->printCertificateInfo();
	}

	PRINT_LINE();

	std::shared_ptr<TimestampCertificateInfo> lTsCertInfo;

	lRetVal = CryptoApiWrapper::GetTimestampCertificateInfo(
		lFileNameWstr,
		lTsCertInfo);

	if (lRetVal == ERROR_SUCCESS)
	{
		lTsCertInfo->printCertificateInfo();
	}

	PRINT_LINE();

	std::wstring lSha256Wstr;
	lRetVal = PeSignatureVerifier::CalculateFileHash(
		lFileNameWstr,
		L"SHA256",
		lSha256Wstr);

	std::wcout << lSha256Wstr.c_str() << std::endl;
	std::wcout << lSha256Wstr.length() << std::endl;
	
	PRINT_LINE();

	lRetVal = PeSignatureVerifier::CheckFileSignature(
		lFileNameWstr);

	std::cout << "File is signed " << bool(lRetVal == 0) << std::endl;






	return lRetVal;
}
