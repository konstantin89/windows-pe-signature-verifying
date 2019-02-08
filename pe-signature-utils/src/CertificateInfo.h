#ifndef __CERTIFICATE_INFO_H
#define __CERTIFICATE_INFO_H

#include <string>

class CertificateInfo
{

public:
	CertificateInfo();
	~CertificateInfo();
	void printCertificateInfo();

public:
	std::wstring subjectName;
	std::wstring issuerName;
	std::wstring signAlgorithm;

};

#endif

