#ifndef __CRYPTO_API_WRAPPER_H
#define __CRYPTO_API_WRAPPER_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>

#include "CertificateInfo.h"

#pragma comment(lib, "crypt32.lib")

class CryptoApiWrapper
{
public:
	static DWORD GetCertificateInfo(
		std::wstring aFileName,
		std::shared_ptr<CertificateInfo> &aCertInfo);

private:

	static DWORD queryCertificateInfo(
		PCCERT_CONTEXT aCertContext,
		DWORD aType,
		std::wstring &aOutputName);

	static DWORD getSignatureAlgoWstring(
		CRYPT_ALGORITHM_IDENTIFIER* pSigAlgo,
		std::wstring &signatureAlgo);

	static DWORD getCertificateContext(
		std::wstring aFileName,
		PCCERT_CONTEXT &aCertContextPtr);

};

#endif
