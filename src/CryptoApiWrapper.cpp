#include "CryptoApiWrapper.h"

#include <vector>

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

DWORD CryptoApiWrapper::GetSignerInfo(
	std::wstring aFileName,
	std::shared_ptr<CMSG_SIGNER_INFO> aSignerInfoPtr)
{
	BOOL lRetVal = TRUE;

	DWORD lEncoding = 0;
	DWORD lContentType = 0;
	DWORD lFormatType = 0;
	HCERTSTORE lStoreHandle = NULL;
	HCRYPTMSG lCryptMsgHandle = NULL;

	DWORD lSignerInfoSize = 0;

	lRetVal = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		aFileName.data(),
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&lEncoding,
		&lContentType,
		&lFormatType,
		&lStoreHandle,
		&lCryptMsgHandle,
		NULL);

	if (!lRetVal)
	{
		return GetLastError();
	}

	lRetVal = CryptMsgGetParam(lCryptMsgHandle,
		CMSG_SIGNER_INFO_PARAM,
		0,
		NULL,
		&lSignerInfoSize);

	if (!lRetVal)
	{
		return GetLastError();
	}

	aSignerInfoPtr = std::make_shared<CMSG_SIGNER_INFO>(new BYTE[lSignerInfoSize]);

	// Get Signer Information.
	lRetVal = CryptMsgGetParam(lCryptMsgHandle,
		CMSG_SIGNER_INFO_PARAM,
		0,
		(PVOID)aSignerInfoPtr.get(),
		&lSignerInfoSize);

	if (!lRetVal)
	{
		return GetLastError();
	}

	return ERROR_SUCCESS;
}


DWORD GetCertificateInfo(
	HCERTSTORE aStoreHandle, 
	PCMSG_SIGNER_INFO pSignerInfo, 
	std::shared_ptr<CertificateInfo> aCertInfo)
{

	if (!aStoreHandle || !pSignerInfo)
	{
		return;
	}

	PCCERT_CONTEXT pCertContext = NULL;
	CERT_INFO CertInfo = { 0 };
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	SYSTEMTIME st;

	// Search for the signer certificate in the temporary 
	// certificate store.
	CertInfo.Issuer = pSignerInfo->Issuer;
	CertInfo.SerialNumber = pSignerInfo->SerialNumber;

	pCertContext = CertFindCertificateInStore(aStoreHandle,
		ENCODING,
		0,
		CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo,
		NULL);

	if (!pCertContext)
	{
		return GetLastError();
	}

	// Print Signer certificate information.
	_tprintf(L"%s:\n\n", aCertName);     //(_T("Signer Certificate:\n\n"));        
	PrintCertificateInfo(pCertContext);
	_tprintf(_T("\n"));

	if (pCounterSignerInfo != NULL)
		LocalFree(pCounterSignerInfo);

	if (pCertContext != NULL)
			CertFreeCertificateContext(pCertContext);
}

DWORD getCertificateName(
	PCCERT_CONTEXT aCertContext,
	DWORD aType,
	std::wstring aOutputName)
{

	DWORD lNameLength;

	lNameLength = CertGetNameString(aCertContext,
		aType,
		CERT_NAME_ISSUER_FLAG,
		NULL,
		NULL,
		0);

	if (!lNameLength)
	{
		return GetLastError();
	}

	std::vector<wchar_t> lNameVector;
	lNameVector.reserve(lNameLength);

	// Get Issuer name.
	lNameLength = CertGetNameString(aCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG,
		NULL,
		lNameVector.data(),
		lNameLength);

	if (!lNameLength)
	{
		return GetLastError();
	}

	aOutputName.assign(lNameVector.data(), lNameLength);

	return ERROR_SUCCESS;
}

