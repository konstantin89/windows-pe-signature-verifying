
#include <iostream>

#include "CryptoApiWrapper.h"

int main()
{
    std::cout << "Hello World!\n"; 

	std::wstring lFileNameWstr(L"C:\\Program Files\\Mozilla Firefox\\firefox.exe");
	std::shared_ptr<CertificateInfo> lCertInfo;

	DWORD lRetVal = CryptoApiWrapper::GetCertificateInfo(
		lFileNameWstr,
		lCertInfo);



	return lRetVal;
}
