#include "PeSignatureVerifier.h"

DWORD PeSignatureVerifier::CheckFileSignature(std::wstring aPePath)
{
	return TrustVerifyWrapper::CheckFileSignature(aPePath);
}

DWORD PeSignatureVerifier::GetCertificateInfo(
	std::wstring aFileName,
	SignerInfoPtr &aCertInfo)
{
	return CryptoApiWrapper::GetCertificateInfo(aFileName, aCertInfo);
}

DWORD PeSignatureVerifier::GetTimestampCertificateInfo(
	std::wstring aFileName,
	TimeStampCertInfoPtr &aCertInfo)
{
	return CryptoApiWrapper::GetTimestampCertificateInfo(aFileName, aCertInfo);
}

DWORD PeSignatureVerifier::CalculateFileHash(
	std::wstring aFileName,
	std::wstring aHashType,
	std::wstring& aHashWstr)
{
	return HashApiWrapper::CalculateFileHash(aFileName, aHashType, aHashWstr);
}