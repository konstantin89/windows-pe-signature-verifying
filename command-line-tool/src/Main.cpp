
#include <iostream>

#include "CryptoApiWrapper.h"
#include "PeSignatureVerifier.h"

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

	std::wstring lSha256Wstr;
	lRetVal = PeSignatureVerifier::CalculateFileHash(
		lFileNameWstr,
		L"SHA256",
		lSha256Wstr);

	std::wcout << lSha256Wstr.c_str() << std::endl;
	std::wcout << lSha256Wstr.length() << std::endl;

	lRetVal = PeSignatureVerifier::CheckFileSignature(
		lFileNameWstr);

	std::cout << "File is signed " << lRetVal << std::endl;


	return lRetVal;
}
