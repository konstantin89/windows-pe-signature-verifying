#include "CryptoApiWrapper.h"

#include <vector>
#include <atlconv.h>

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

DWORD CryptoApiWrapper::getCertificateContext(
	std::wstring aFileName,
	PCCERT_CONTEXT &aCertContextPtr)
{
	BOOL lRetVal = TRUE;

	DWORD lEncoding = 0;
	DWORD lContentType = 0;
	DWORD lFormatType = 0;
	HCERTSTORE lStoreHandle = NULL;
	HCRYPTMSG lCryptMsgHandle = NULL;

	PCCERT_CONTEXT pCertContext = NULL;
	CERT_INFO CertInfo = { 0 };

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

	PCMSG_SIGNER_INFO lSignerInfoPtr = (PCMSG_SIGNER_INFO) new BYTE[lSignerInfoSize];

	// Get Signer Information.
	lRetVal = CryptMsgGetParam(lCryptMsgHandle,
		CMSG_SIGNER_INFO_PARAM,
		0,
		(PVOID)lSignerInfoPtr,
		&lSignerInfoSize);

	if (!lRetVal)
	{
		delete lSignerInfoPtr;
		return GetLastError();
	}

	CertInfo.Issuer = lSignerInfoPtr->Issuer;
	CertInfo.SerialNumber = lSignerInfoPtr->SerialNumber;

	pCertContext = CertFindCertificateInStore(lStoreHandle,
		ENCODING,
		0,
		CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo,
		NULL);

	if (!pCertContext)
	{
		delete lSignerInfoPtr;
		return GetLastError();
	}

	aCertContextPtr = pCertContext;

	delete lSignerInfoPtr;
	return ERROR_SUCCESS;
}

DWORD CryptoApiWrapper::GetCertificateInfo(
	std::wstring aFileName,
	std::shared_ptr<CertificateInfo> &aCertInfo)
{

	DWORD lRetVal = ERROR_SUCCESS;

	PCCERT_CONTEXT lCertContextPtr = NULL;

	lRetVal = getCertificateContext(aFileName, lCertContextPtr);

	if (lRetVal != ERROR_SUCCESS)
	{
		return GetLastError();
	}

	aCertInfo = std::make_shared<CertificateInfo>();

	std::wstring lIssuerName;
	lRetVal = queryCertificateInfo(lCertContextPtr, CERT_NAME_ISSUER_FLAG, lIssuerName);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->issuerName = lIssuerName;
	}

	std::wstring lSubjectName;
	lRetVal = queryCertificateInfo(lCertContextPtr, 0, lSubjectName);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->subjectName = lSubjectName;
	}

	std::wstring lSignAlgorithm;
	lRetVal = getSignatureAlgoWstring(&lCertContextPtr->pCertInfo->SignatureAlgorithm, lSignAlgorithm);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->signAlgorithm = lSignAlgorithm;
	}

	if (lCertContextPtr)
	{
		CertFreeCertificateContext(lCertContextPtr);
	}
	
	return ERROR_SUCCESS;
}

DWORD CryptoApiWrapper::queryCertificateInfo(
	PCCERT_CONTEXT aCertContext,
	DWORD aType,
	std::wstring &aOutputName)
{

	DWORD lNameLength;

	lNameLength = CertGetNameString(aCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		aType,
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
		aType,
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

DWORD CryptoApiWrapper::getSignatureAlgoWstring(
	CRYPT_ALGORITHM_IDENTIFIER* pSigAlgo, 
	std::wstring &signatureAlgo)
{
	if (!pSigAlgo || !pSigAlgo->pszObjId)
	{
		return ERROR_INVALID_PARAMETER;
	}
	
	PCCRYPT_OID_INFO pCOI = ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pSigAlgo->pszObjId, 0);
	if (!pCOI)
	{
		return GetLastError();
	}
	if (pCOI &&	pCOI->pwszName)
	{
		signatureAlgo.assign(pCOI->pwszName);
	}
	else
	{
		USES_CONVERSION;
		signatureAlgo.assign(A2W(pSigAlgo->pszObjId));
	}
	
	return ERROR_SUCCESS;
}