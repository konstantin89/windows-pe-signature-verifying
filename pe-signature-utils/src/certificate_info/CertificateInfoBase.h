#ifndef __CERTIFICATE_INFO_BASE_H
#define __CERTIFICATE_INFO_BASE_H

#include <string>
#include <iostream>

class CertificateInfoBase
{

public:
	CertificateInfoBase() {};
	virtual ~CertificateInfoBase() {};

	virtual void PrintCertificateInfo()
	{
		std::wcout << "Serial number: " << serialNumber.c_str() << std::endl;
		std::wcout << "Issuer name: " << issuerName.c_str() << std::endl;
		std::wcout << "Subject name: " << subjectName.c_str() << std::endl;
		std::wcout << "Signing algorithm: " << signAlgorithm.c_str() << std::endl;
	};

public:
	std::wstring serialNumber;
	std::wstring subjectName;
	std::wstring issuerName;
	std::wstring signAlgorithm;
};

#endif
