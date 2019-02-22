#ifndef __TIMESTAMP_CERTIFICATE_INFO_H
#define __TIMESTAMP_CERTIFICATE_INFO_H

#include "CertificateInfoBase.h"
#include <memory>
#include <Windows.h>

class TimestampCertificateInfo : public CertificateInfoBase
{

public:

	using TimmeStampCertPtr = std::shared_ptr<TimestampCertificateInfo>;

	TimestampCertificateInfo();
	virtual ~TimestampCertificateInfo();
	virtual void PrintCertificateInfo() override;
	std::wstring GetDateAsWstr();

public:
	std::shared_ptr<SYSTEMTIME> dateOfTimeStamp;
};

#endif