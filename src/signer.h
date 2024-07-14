#pragma once
#include <string>

class PKCS11;

namespace Signer
{
	std::string signEnveloped(const std::string& xml, const PKCS11& pkcs11, bool XAdES = false);
}