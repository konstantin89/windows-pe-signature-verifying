#pragma once

#include ".\certificate_info\SignerInfo.h"
#include ".\native_api_wrappers\CryptoApiWrapper.h"
#include ".\native_api_wrappers\HashApiWrapper.h"
#include ".\native_api_wrappers\TrustVerifyWrapper.h"

class PeSignatureVerifier
{
public:

	using SignerInfoPtr = CryptoApiWrapper::SignerInfoPtr;
	using TimeStampCertInfoPtr = CryptoApiWrapper::TimeStampCertInfoPtr;

	/**
	* @brief: Check if the given file is signed with valid certificate.
	* @returns: ERROR_SUCCESS iff the PE's signature is verified, otherwise returns error code.
	*/
	static DWORD CheckFileSignature(
		__in std::wstring aPePath);

	/**
	* @brief: Calculate hash for a given file.
	* 
	* @param: aFileName - Full path of file for hash calculation.
	* @param: aHashType - Hash algorithm to use. For example L"SHA256".
	* @param: aHashWstr - Wstring containing the calculated hash.
	*
	* @returns: ERROR_SUCCESS iff call is successful, otherwise returns error code.
	*
	*/
	static DWORD CalculateFileHash(
		__in  std::wstring aFileName,
		__in  std::wstring aHashType,
		__out std::wstring& aHashWstr);

	/**
	* @brief: Get info about the certificate used to sign the file.
	*
	* @returns: ERROR_SUCCESS iff call is successful, otherwise returns error code.
	*
	*/
	static DWORD GetCertificateInfo(
		__in  std::wstring aFileName,
		__out SignerInfoPtr &aCertInfo);

	/**
	* @brief: Get info about the time stamp certificate used to sign the file.
	*
	* @returns: ERROR_SUCCESS iff call is successful, otherwise returns error code.
	*
	*/
	static DWORD GetTimestampCertificateInfo(
		std::wstring aFileName,
		TimeStampCertInfoPtr &aCertInfo);
};
