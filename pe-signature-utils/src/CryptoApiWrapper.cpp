#include "CryptoApiWrapper.h"

#include <vector>
#include <atlconv.h>
#include <wchar.h>

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)


DWORD CryptoApiWrapper::GetCertificateInfo(
	std::wstring aFileName,
	std::shared_ptr<SignerInfo> &aCertInfo)
{

	DWORD lRetVal = ERROR_SUCCESS;

	PCCERT_CONTEXT lCertContextPtr = NULL;

	lRetVal = getCertificateContext(
		aFileName, 
		RequestedContexType::Signer, 
		lCertContextPtr);

	if (lRetVal != ERROR_SUCCESS)
	{
		return GetLastError();
	}

	aCertInfo = std::make_shared<SignerInfo>();

	std::wstring lSerialNumber;
	lRetVal = getCertificateSerialNumber(lCertContextPtr, lSerialNumber);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->serialNumber = lSerialNumber;
	}

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

DWORD CryptoApiWrapper::GetTimestampCertificateInfo(
	std::wstring aPePath,
	std::shared_ptr <TimestampCertificateInfo> &aCertificateInfo)
{
	UNREFERENCED_PARAMETER(aPePath);
	UNREFERENCED_PARAMETER(aCertificateInfo);

	return ERROR_SUCCESS;
}


DWORD CryptoApiWrapper::getCertificateContext(
	std::wstring aFileName,
	RequestedContexType aRequestedContextType,
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

	PCMSG_SIGNER_INFO lCounterSignerInfoPtr = NULL;


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

	if (aRequestedContextType == RequestedContexType::Signer)
	{
		CertInfo.Issuer = lSignerInfoPtr->Issuer;
		CertInfo.SerialNumber = lSignerInfoPtr->SerialNumber;
	}

	else if (aRequestedContextType == RequestedContexType::TimeStamp)
	{
		lRetVal = getTimeStampSignerInfo(lSignerInfoPtr, &lCounterSignerInfoPtr);

		if (lRetVal != ERROR_SUCCESS)
		{
			return lRetVal;
		}

		CertInfo.Issuer = lCounterSignerInfoPtr->Issuer;
		CertInfo.SerialNumber = lCounterSignerInfoPtr->SerialNumber;
	}

	else 
	{
		return ERROR_INVALID_PARAMETER;
	}

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


DWORD CryptoApiWrapper::getTimeStampSignerInfo(
	PCMSG_SIGNER_INFO pSignerInfo, 
	PCMSG_SIGNER_INFO *pCounterSignerInfo)
{
	BOOL fResult;
	DWORD dwSize;

	*pCounterSignerInfo = NULL;

	// Loop through unathenticated attributes for
	// szOID_RSA_counterSign OID.
	for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
	{
		if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
			szOID_RSA_counterSign) == 0)
		{
			// Get size of CMSG_SIGNER_INFO structure.
			fResult = CryptDecodeObject(ENCODING,
				PKCS7_SIGNER_INFO,
				pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				NULL,
				&dwSize);
			if (!fResult)
			{
				return GetLastError();
			}

			// Allocate memory for CMSG_SIGNER_INFO.
			*pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
			if (!*pCounterSignerInfo)
			{
				return GetLastError();
			}

			// Decode and get CMSG_SIGNER_INFO structure
			// for timestamp certificate.
			fResult = CryptDecodeObject(ENCODING,
				PKCS7_SIGNER_INFO,
				pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)*pCounterSignerInfo,
				&dwSize);
			if (!fResult)
			{
				return GetLastError();
			}

			break; // Break from for loop.
		}
	}
	return ERROR_SUCCESS;
}

DWORD CryptoApiWrapper::getCertificateSerialNumber(
	PCCERT_CONTEXT aCertContext,
	std::wstring &aSerialNumberWstr)
{
	if (!aCertContext)
	{
		return ERROR_INVALID_PARAMETER;
	}

	const int lBufferSize = 3;

	wchar_t lTempBuffer[lBufferSize] = { 0 };

	aSerialNumberWstr = L"";

	auto lDataBytesCount = aCertContext->pCertInfo->SerialNumber.cbData;
	for (DWORD n = 0; n < lDataBytesCount; n++)
	{

		auto lSerialByte = aCertContext->pCertInfo->SerialNumber.pbData[lDataBytesCount - (n + 1)];

		swprintf(lTempBuffer, lBufferSize*2, L"%02x", lSerialByte);

		aSerialNumberWstr += std::wstring(lTempBuffer, 2);

	}

	return ERROR_SUCCESS;
}