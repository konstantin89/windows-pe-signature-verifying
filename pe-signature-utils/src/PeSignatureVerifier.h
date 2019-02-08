#ifndef __PE_SIGNATURE_VERIFIER_H
#define __PE_SIGNATURE_VERIFIER_H

#include <windows.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>

#include <string>
#include <iostream>
#include <memory>

#include "CertificateInfo.h"

class PeSignatureVerifier
{
public:

	/**
	* @brief: Check if the given file is signed with valid certificate.
	* @returns: ERROR_SUCCESS iff the PE's signature is verified, othervise returns error code.
	*/
	static DWORD CheckFileSignature(std::wstring aPePath);

	/**
	*
	*/
	static DWORD GetCertificateInfo(
		std::wstring aPePath, 
		CertificateInfo& aCertificateInfo);

	/**
	*
	*/
	static DWORD CalculateFileHash(
		std::wstring aFileName,
		std::wstring aHashType,
		std::wstring& aHashWstr);

private:

	/**
	* @brief: Try to verify PE from signature embeeded in it.
	* @param: aPePath - Path of the PE to verify.
	*/
	static DWORD verifyFromFile(std::wstring aPePath);

	/**
	* @param: aPePath - Path of the PE to verify.
	* @param: aCatalogHashAlgo - Hash algorithm used by Windows signature catalogue system.
	*                            Note that Windows 8 and 10 use SHA256 in theie catalogues,
	*                            while older versions may use SHA1.
	*                            For additional information please visit the attached link.
	*
	*@link: https://stackoverflow.com/questions/26216789/getting-digital-signature-from-mmc-exe-at-windows-8
	*
	*/
	static DWORD verifyFromCatalog(
		std::wstring aPePath, 
		std::wstring aCatalogHashAlgo);

	static DWORD verifyTrustFromCatObject(
		HCATINFO aCatInfo,
		std::wstring aFileName,
		std::wstring aHash);

	static std::wstring byteHashIntoWstring(BYTE* aHash, size_t aHashLen);
};


#endif