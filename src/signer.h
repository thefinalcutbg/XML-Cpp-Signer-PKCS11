#pragma once
#include <string>

class PKCS11;

namespace Signer
{
	//Returns the only the signature node. Signes the whole content of the given xml document.
	std::string getSignature(const std::string& xml, const PKCS11& pkcs11, const std::string& refUri = "", bool XAdES = false);
	//Returns the given xml document plus enveloped signature node
	std::string signEnveloped(const std::string& xml, const PKCS11& pkcs11, bool XAdES = false);
}