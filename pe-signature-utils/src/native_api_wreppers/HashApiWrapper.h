#pragma once 

#include <Windows.h>
#include <string>

class HashApiWrapper
{
public:

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
	static std::wstring ByteHashIntoWstring(
		BYTE* aHash, 
		size_t aHashLen);

};