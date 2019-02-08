#ifndef __TIMESTAMP_CERTIFICATE_INFO_H
#define __TIMESTAMP_CERTIFICATE_INFO_H

#include <string>
#include <memory>
#include <Windows.h>

class TimestampCertificateInfo {

public:
	std::wstring getTimeStampAsWstr();
	void printTimestampCertificate();


public:
	//Serial Number

	std::wstring subjectName;
	std::wstring issuerName;
	std::wstring signAlgorithm;
	std::shared_ptr<SYSTEMTIME> dateOfTimeStamp;
};

#endif