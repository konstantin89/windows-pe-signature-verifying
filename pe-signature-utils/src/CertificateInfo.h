#ifndef __CERTIFICATE_INFO_H
#define __CERTIFICATE_INFO_H

#include <string>

struct CertificateInfo
{
	std::wstring subjectName;
	std::wstring issuerName;
	std::wstring signAlgorithm;
};

#endif

