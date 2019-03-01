#ifndef __SIGNER_INFO_H
#define __SIGNER_INFO_H

#include <memory>
#include "CertificateInfoBase.h"

class SignerInfo : public CertificateInfoBase
{

public:

	using SignerInfoPtr = std::shared_ptr<SignerInfo>;

	SignerInfo() { /* EMPTY*/ };
	virtual ~SignerInfo() { /* EMPTY*/ };
};

#endif

