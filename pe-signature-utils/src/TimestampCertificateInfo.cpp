#include "TimestampCertificateInfo.h"
#include <cwchar>

TimestampCertificateInfo::TimestampCertificateInfo()
{
	/* EMPTY */
}

TimestampCertificateInfo::~TimestampCertificateInfo()
{
	/* EMPTY */
}

void TimestampCertificateInfo::PrintCertificateInfo()
{
	auto lDateWstr = GetDateAsWstr();

	CertificateInfoBase::PrintCertificateInfo();
	std::wcout << L"Date of timestamp: " << lDateWstr.c_str() << std::endl;
}

std::wstring TimestampCertificateInfo::GetDateAsWstr()
{
	if (dateOfTimeStamp == NULL) {
		return L"";
	}

	const int lBufSize = 100;
	wchar_t lStrBuf[lBufSize];

	int lDateStrLen = swprintf(
		lStrBuf, 
		lBufSize, 
		L"%02d/%02d/%04d %02d:%02d",
		dateOfTimeStamp->wDay,
		dateOfTimeStamp->wMonth,
		dateOfTimeStamp->wYear,
		dateOfTimeStamp->wHour,
		dateOfTimeStamp->wMinute);

	return std::wstring(lStrBuf, lDateStrLen);
}
