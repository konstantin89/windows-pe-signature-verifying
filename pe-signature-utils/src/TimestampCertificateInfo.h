#ifndef __TIMESTAMP_CERTIFICATE_INFO_H
#define __TIMESTAMP_CERTIFICATE_INFO_H

#include "CertificateInfoBase.h"
#include <memory>
#include <Windows.h>

class TimestampCertificateInfo : public CertificateInfoBase
{

public:
	TimestampCertificateInfo();
	virtual ~TimestampCertificateInfo();
	virtual void printCertificateInfo() override;


public:
	std::shared_ptr<SYSTEMTIME> dateOfTimeStamp;
};

#endif