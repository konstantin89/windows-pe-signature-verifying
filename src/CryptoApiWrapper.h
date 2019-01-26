#ifndef __CRYPTO_API_WRAPPER_H
#define __CRYPTO_API_WRAPPER_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>

#include "CertificateInfo.h"


class CryptoApiWrapper
{
public:
	static DWORD GetSignerInfo(
		std::wstring aFileName,
		std::shared_ptr<CMSG_SIGNER_INFO> aSignerInfoPtr);

private:

};



#endif
