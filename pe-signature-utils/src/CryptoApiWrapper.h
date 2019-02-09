#ifndef __CRYPTO_API_WRAPPER_H
#define __CRYPTO_API_WRAPPER_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>

#include "CertificateInfo.h"
#include "TimestampCertificateInfo.h"

#pragma comment(lib, "crypt32.lib")

class CryptoApiWrapper
{
public:

	/**
	*
	*/
	static DWORD GetCertificateInfo(
		std::wstring aFileName,
		std::shared_ptr<CertificateInfo> &aCertInfo);

	/**
	*
	*/
	static DWORD GetTimestampCertificateInfo(
		std::wstring aPePath,
		std::shared_ptr <TimestampCertificateInfo> &aCertificateInfo);

private:

	enum RequestedContexType {Signer, TimeStamp};

	static DWORD queryCertificateInfo(
		PCCERT_CONTEXT aCertContext,
		DWORD aType,
		std::wstring &aOutputName);

	static DWORD getSignatureAlgoWstring(
		CRYPT_ALGORITHM_IDENTIFIER* pSigAlgo,
		std::wstring &signatureAlgo);

	static DWORD getCertificateContext(
		std::wstring aFileName,
		RequestedContexType aRequestedContextType,
		PCCERT_CONTEXT &aCertContextPtr);

	static DWORD getTimeStampSignerInfo(
		PCMSG_SIGNER_INFO pSignerInfo,
		PCMSG_SIGNER_INFO *pCounterSignerInfo);

	static DWORD getCertificateSerialNumber(
		PCCERT_CONTEXT aCertContext, 
		std::wstring &aSerialNumberWstr);

};

#endif
