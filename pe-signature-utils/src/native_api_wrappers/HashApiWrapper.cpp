#include "HashApiWrapper.h"

#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>

DWORD HashApiWrapper::CalculateFileHash(
	std::wstring aFileName,
	std::wstring aHashType,
	std::wstring& aHashWstr)
{
	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
	HANDLE hFile;
	DWORD dwHash;
	BYTE bHash[100];
	HCATINFO hCatInfo = NULL;
	HCATADMIN hCatAdmin;

	hFile = CreateFileW(aFileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}

	if (!CryptCATAdminAcquireContext2(
		&hCatAdmin,
		&DriverActionGuid,
		aHashType.c_str(),
		NULL,
		0))
	{
		CloseHandle(hFile);
		return GetLastError();
	}

	dwHash = sizeof(bHash);
	if (!CryptCATAdminCalcHashFromFileHandle2(
		hCatAdmin,
		hFile,
		&dwHash,
		bHash,
		0))
	{
		CloseHandle(hFile);
		return GetLastError();
	}

	CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
	CryptCATAdminReleaseContext(hCatAdmin, 0);
	CloseHandle(hFile);

	aHashWstr = ByteHashIntoWstring(bHash, dwHash);

	return ERROR_SUCCESS;
}

std::wstring HashApiWrapper::ByteHashIntoWstring(BYTE* aHash, size_t aHashLen)
{
	if (!aHash || !aHashLen)
	{
		return L"";
	}

	auto lHashString = new WCHAR[aHashLen * 2 + 1];

	for (DWORD dw = 0; dw < aHashLen; ++dw)
	{
		wsprintfW(&lHashString[dw * 2], L"%02X", aHash[dw]);
	}

	std::wstring lHashWstr(lHashString);

	delete[] lHashString;

	return lHashWstr;
}