
#include "TrustVerifyWrapper.h"
#include "HashApiWrapper.h"

#pragma comment(lib, "wintrust")

#define SHA256 L"SHA256"

DWORD TrustVerifyWrapper::CheckFileSignature(std::wstring aPePath)
{
	// Try to find embeeded signature in the given PE.
	if (verifyFromFile(aPePath) == ERROR_SUCCESS)
	{
		return ERROR_SUCCESS;
	}

	// Calculate the hash for the given PE and look for in Windows catalogs.
	return verifyFromCatalog(aPePath, SHA256);
}

DWORD TrustVerifyWrapper::verifyFromFile(std::wstring aPePath)
{
	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	GUID DriverActionGuid = DRIVER_ACTION_VERIFY;

	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };

	////set up structs to verify files with cert signatures
	memset(&wfi, 0, sizeof(wfi));
	wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
	wfi.pcwszFilePath = aPePath.c_str();
	wfi.hFile = NULL;
	wfi.pgKnownSubject = NULL;

	memset(&wd, 0, sizeof(wd));
	wd.cbStruct = sizeof(WINTRUST_DATA);
	wd.dwUnionChoice = WTD_CHOICE_FILE;
	wd.pFile = &wfi;
	wd.dwUIChoice = WTD_UI_NONE;
	wd.fdwRevocationChecks = WTD_REVOKE_NONE;
	wd.dwStateAction = 0;
	wd.dwProvFlags = WTD_SAFER_FLAG;
	wd.hWVTStateData = NULL;
	wd.pwszURLReference = NULL;
	wd.pPolicyCallbackData = NULL;
	wd.pSIPClientData = NULL;
	wd.dwUIContext = 0;

	return WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
}

DWORD TrustVerifyWrapper::verifyFromCatalog(
	std::wstring aPePath,
	std::wstring aCatalogHashAlgo)
{
	LONG lStatus = TRUST_E_NOSIGNATURE;
	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
	HANDLE hFile;
	DWORD dwHash;
	BYTE bHash[100];
	HCATINFO hCatInfo = NULL;
	HCATADMIN hCatAdmin;

	hFile = CreateFileW(aPePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}

	if (!CryptCATAdminAcquireContext2(
		&hCatAdmin,
		&DriverActionGuid,
		aCatalogHashAlgo.c_str(),
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

	auto lHashWstr = HashApiWrapper::ByteHashIntoWstring(bHash, dwHash);

	/*
	* Find the calalogue that contains hash of our file.
	* Note that CryptCATAdminEnumCatalogFromHash gives you
	* the ability to iterate over all the catalogues that are
	* containing your hash.
	*/
	hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);

	if (!hCatInfo)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		CloseHandle(hFile);
		return GetLastError();
	}

	lStatus = verifyTrustFromCatObject(hCatInfo, aPePath, lHashWstr);

	CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
	CryptCATAdminReleaseContext(hCatAdmin, 0);
	CloseHandle(hFile);

	return lStatus;

}


DWORD TrustVerifyWrapper::verifyTrustFromCatObject(
	HCATINFO aCatInfo,
	std::wstring aFileName,
	std::wstring aHash)
{
	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA wd = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };

	CATALOG_INFO ci = { 0 };
	CryptCATCatalogInfoFromContext(aCatInfo, &ci, 0);

	memset(&wci, 0, sizeof(wci));
	wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
	wci.pcwszCatalogFilePath = ci.wszCatalogFile;
	wci.pcwszMemberFilePath = aFileName.c_str();
	wci.pcwszMemberTag = aHash.c_str();

	memset(&wd, 0, sizeof(wd));
	wd.cbStruct = sizeof(WINTRUST_DATA);
	wd.fdwRevocationChecks = WTD_REVOKE_NONE;
	wd.dwUnionChoice = WTD_CHOICE_CATALOG;
	wd.pCatalog = &wci;
	wd.dwUIChoice = WTD_UI_NONE;
	wd.dwUIContext = WTD_UICONTEXT_EXECUTE;
	wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
	wd.dwStateAction = WTD_STATEACTION_VERIFY;
	wd.dwProvFlags = 0;
	wd.hWVTStateData = NULL;
	wd.pwszURLReference = NULL;
	wd.pPolicyCallbackData = NULL;
	wd.pSIPClientData = NULL;
	wd.dwUIContext = 0;

	return WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
}
