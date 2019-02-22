#ifndef __PE_SIGNATURE_VERIFIER_H
#define __PE_SIGNATURE_VERIFIER_H

#include <string>
#include <iostream>
#include <memory>

#include "SignerInfo.h"
#include "CryptoApiWrapper.h"

class PeSignatureVerifier
{
public:

	using SignerInfoPtr = CryptoApiWrapper::SignerInfoPtr;
	using TimeStampCertInfoPtr = CryptoApiWrapper::TimeStampCertInfoPtr;

	/**
	* @brief: Check if the given file is signed with valid certificate.
	* @returns: ERROR_SUCCESS iff the PE's signature is verified, othervise returns error code.
	*/
	static DWORD CheckFileSignature(std::wstring aPePath);

	/**
	*
	*/
	static DWORD CalculateFileHash(
		std::wstring aFileName,
		std::wstring aHashType,
		std::wstring& aHashWstr);

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

};


#endif