#include "CertificateInfo.h"
#include <iostream>

CertificateInfo::CertificateInfo()
{
	subjectName = L"";
	issuerName = L"";
	signAlgorithm = L"";
	serialNumber = L"";
}

CertificateInfo::~CertificateInfo()
{
	/* EMPTY */
}

void CertificateInfo::printCertificateInfo() 
{
	std::wcout << "Serial number: " << serialNumber.c_str() << std::endl;
	std::wcout << "Subject name: " << subjectName.c_str() << std::endl;
	std::wcout << "Issuer name: " << issuerName.c_str() << std::endl;
	std::wcout << "Signing algorithm: " << signAlgorithm.c_str() << std::endl;

}
