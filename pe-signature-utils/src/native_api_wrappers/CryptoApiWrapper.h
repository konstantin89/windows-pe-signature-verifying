#ifndef __CRYPTO_API_WRAPPER_H
#define __CRYPTO_API_WRAPPER_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>

#include ".\..\certificate_info\SignerInfo.h"
#include ".\..\certificate_info\\TimestampCertificateInfo.h"

#pragma comment(lib, "crypt32.lib")

class CryptoApiWrapper
{
public:

	using SignerInfoPtr = SignerInfo::SignerInfoPtr;
	using TimeStampCertInfoPtr = TimestampCertificateInfo::TimmeStampCertPtr;

	/**
	*
	*/
	static DWORD GetCertificateInfo(
		std::wstring aFileName,
		SignerInfoPtr &aCertInfo);

	/**
	*
	*/
	static DWORD GetTimestampCertificateInfo(
		std::wstring aFileName,
		TimeStampCertInfoPtr &aCertInfo);

private:

	static DWORD queryCertificateInfo(
		PCCERT_CONTEXT aCertContext,
		DWORD aType,
		std::wstring &aOutputName);

	static DWORD getSignatureAlgoWstring(
		CRYPT_ALGORITHM_IDENTIFIER* pSigAlgo,
		std::wstring &signatureAlgo);

	static DWORD getCertificateContext(
		std::shared_ptr<CMSG_SIGNER_INFO> aSignerInfo,
		HCERTSTORE aCertStore,
		PCCERT_CONTEXT &aCertContextPtr);

	static DWORD getTimeStampSignerInfo(
		std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo,
		std::shared_ptr<CMSG_SIGNER_INFO> &aCounterSignerInfo);

	static DWORD getCertificateSerialNumber(
		PCCERT_CONTEXT aCertContext, 
		std::wstring &aSerialNumberWstr);

	static DWORD getSignerInfo(
		std::wstring aFileName,
		std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo,
		HCERTSTORE &aCertStore);

	static bool getDateOfTimeStamp(
		std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo,
		std::shared_ptr<SYSTEMTIME> &aSysTime);

};

#endif
