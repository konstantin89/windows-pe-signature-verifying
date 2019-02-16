#include "CryptoApiWrapper.h"

#include <vector>
#include <atlconv.h>
#include <wchar.h>

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)


DWORD CryptoApiWrapper::GetCertificateInfo(
	std::wstring aFileName,
	CryptoApiWrapper::SignerInfoPtr &aCertInfo)
{
	HCERTSTORE lCertStore;
	std::shared_ptr<CMSG_SIGNER_INFO> lSignerInfo;
	DWORD lRetVal = ERROR_SUCCESS;
	PCCERT_CONTEXT lCertContexPtr = NULL;

	lRetVal = getSignerInfo(aFileName, lSignerInfo, lCertStore);
	if (lRetVal != ERROR_SUCCESS)
	{
		return lRetVal;
	}

	lRetVal = getCertificateContext(lSignerInfo, lCertStore, lCertContexPtr);
	if (lRetVal != ERROR_SUCCESS)
	{
		return lRetVal;
	}

	aCertInfo = std::make_shared<SignerInfo>();

	std::wstring lSerialNumber;
	lRetVal = getCertificateSerialNumber(lCertContexPtr, lSerialNumber);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->serialNumber = lSerialNumber;
	}

	std::wstring lIssuerName;
	lRetVal = queryCertificateInfo(lCertContexPtr, CERT_NAME_ISSUER_FLAG, lIssuerName);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->issuerName = lIssuerName;
	}

	std::wstring lSubjectName;
	lRetVal = queryCertificateInfo(lCertContexPtr, 0, lSubjectName);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->subjectName = lSubjectName;
	}

	std::wstring lSignAlgorithm;
	lRetVal = getSignatureAlgoWstring(&lCertContexPtr->pCertInfo->SignatureAlgorithm, lSignAlgorithm);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->signAlgorithm = lSignAlgorithm;
	}

	if (lCertContexPtr)
	{
		CertFreeCertificateContext(lCertContexPtr);
	}
	
	return ERROR_SUCCESS;
}

DWORD CryptoApiWrapper::GetTimestampCertificateInfo(
	std::wstring aFileName,
	CryptoApiWrapper::TimeStampCertInfoPtr &aCertInfo)
{
	HCERTSTORE lCertStore;
	std::shared_ptr<CMSG_SIGNER_INFO> lSignerInfo;
	std::shared_ptr<CMSG_SIGNER_INFO> lTimeStammpSignerInfo;
	DWORD lRetVal = ERROR_SUCCESS;
	PCCERT_CONTEXT lCertContexPtr = NULL;

	lRetVal = getSignerInfo(aFileName, lSignerInfo, lCertStore);
	if (lRetVal != ERROR_SUCCESS) 
	{
		return lRetVal;
	}

	lRetVal = getCertificateContext(lSignerInfo, lCertStore, lCertContexPtr);
	if (lRetVal != ERROR_SUCCESS) 
	{
		return lRetVal;
	}

	lRetVal = getTimeStampSignerInfo(lSignerInfo, lTimeStammpSignerInfo);
	if (lRetVal != ERROR_SUCCESS)
	{
		return lRetVal;
	}

	lRetVal = getCertificateContext(lTimeStammpSignerInfo, lCertStore, lCertContexPtr);
	if (lRetVal != ERROR_SUCCESS)
	{
		return lRetVal;
	}

	aCertInfo = std::make_shared<TimestampCertificateInfo>();

	std::wstring lSerialNumber;
	lRetVal = getCertificateSerialNumber(lCertContexPtr, lSerialNumber);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->serialNumber = lSerialNumber;
	}

	std::wstring lIssuerName;
	lRetVal = queryCertificateInfo(lCertContexPtr, CERT_NAME_ISSUER_FLAG, lIssuerName);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->issuerName = lIssuerName;
	}

	std::wstring lSubjectName;
	lRetVal = queryCertificateInfo(lCertContexPtr, 0, lSubjectName);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->subjectName = lSubjectName;
	}

	std::wstring lSignAlgorithm;
	lRetVal = getSignatureAlgoWstring(&lCertContexPtr->pCertInfo->SignatureAlgorithm, lSignAlgorithm);
	if (lRetVal == ERROR_SUCCESS)
	{
		aCertInfo->signAlgorithm = lSignAlgorithm;
	}

	std::shared_ptr<SYSTEMTIME> lSysTime;
	bool lBoolRetVal = getDateOfTimeStamp(lTimeStammpSignerInfo, lSysTime);
	if (lBoolRetVal == true)
	{
		aCertInfo->dateOfTimeStamp = lSysTime;
	}

	if (lCertContexPtr)
	{
		CertFreeCertificateContext(lCertContexPtr);
	}

	return ERROR_SUCCESS;
}

DWORD CryptoApiWrapper::getSignerInfo(
	std::wstring aFileName,
	std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo,
	HCERTSTORE &aCertStore)
{
	BOOL lRetVal = TRUE;
	DWORD lEncoding = 0;
	DWORD lContentType = 0;
	DWORD lFormatType = 0;
	HCERTSTORE lStoreHandle = NULL;
	HCRYPTMSG lCryptMsgHandle = NULL;

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

	aSignerInfo = std::shared_ptr<CMSG_SIGNER_INFO>(lSignerInfoPtr);
	aCertStore = lStoreHandle;

	return ERROR_SUCCESS;
}

DWORD CryptoApiWrapper::getCertificateContext(
	std::shared_ptr<CMSG_SIGNER_INFO> aSignerInfo,
	HCERTSTORE aCertStore,
	PCCERT_CONTEXT &aCertContextPtr)
{

	PCCERT_CONTEXT pCertContext = NULL;
	CERT_INFO CertInfo = { 0 };

	CertInfo.Issuer = aSignerInfo->Issuer;
	CertInfo.SerialNumber = aSignerInfo->SerialNumber;
	
	pCertContext = CertFindCertificateInStore(
		aCertStore,
		ENCODING,
		0,
		CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo,
		NULL);

	if (!pCertContext)
	{
		return GetLastError();
	}

	aCertContextPtr = pCertContext;

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
	std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo,
	std::shared_ptr<CMSG_SIGNER_INFO> &aCounterSignerInfo)
{
	BOOL lRetValBool;
	DWORD dwSize;
	bool lFoundCounterSign = false;

	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	aCounterSignerInfo = NULL;

	// Loop through unathenticated attributes for
	// szOID_RSA_counterSign OID.
	for (DWORD n = 0; n < aSignerInfo->UnauthAttrs.cAttr; n++)
	{
		if (lstrcmpA(aSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
			szOID_RSA_counterSign) == 0)
		{
			// Get size of CMSG_SIGNER_INFO structure.
			lRetValBool = CryptDecodeObject(ENCODING,
				PKCS7_SIGNER_INFO,
				aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
				aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				NULL,
				&dwSize);
			if (!lRetValBool)
			{
				return GetLastError();
			}

			// Allocate memory for CMSG_SIGNER_INFO.
			pCounterSignerInfo = (PCMSG_SIGNER_INFO) new BYTE[dwSize];
			if (!pCounterSignerInfo)
			{
				return GetLastError();
			}

			// Decode and get CMSG_SIGNER_INFO structure
			// for timestamp certificate.
			lRetValBool = CryptDecodeObject(ENCODING,
				PKCS7_SIGNER_INFO,
				aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
				aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)pCounterSignerInfo,
				&dwSize);

			if (!lRetValBool)
			{
				return GetLastError();
			}

			lFoundCounterSign = true;

			break;
		}
	}
	
	if (lFoundCounterSign)
	{
		aCounterSignerInfo = std::shared_ptr<CMSG_SIGNER_INFO>(pCounterSignerInfo);
		return ERROR_SUCCESS;
	}
	else 
	{
		return ERROR_GEN_FAILURE;
	}
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


bool CryptoApiWrapper::getDateOfTimeStamp(
	std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo, 
	std::shared_ptr<SYSTEMTIME> &aSysTime)
{
	FILETIME lft, ft;
	DWORD dwData;
	aSysTime = std::make_shared<SYSTEMTIME>();

	DWORD lRetVal = false;

	// Loop through authenticated attributes and find
	// szOID_RSA_signingTime OID.
	for (DWORD n = 0; n < aSignerInfo->AuthAttrs.cAttr; n++)
	{
		if (lstrcmpA(szOID_RSA_signingTime,
			aSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			// Decode and get FILETIME structure.
			dwData = sizeof(ft);
			lRetVal = CryptDecodeObject(ENCODING,
				szOID_RSA_signingTime,
				aSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				aSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)&ft,
				&dwData);

			if (!lRetVal)
			{
				break;
			}

			// Convert to local time.
			FileTimeToLocalFileTime(&ft, &lft);
			FileTimeToSystemTime(&lft, aSysTime.get());

			lRetVal = true;

			break; // Break from for loop.

		} //lstrcmp szOID_RSA_signingTime
	} // for 

	return lRetVal;
}
