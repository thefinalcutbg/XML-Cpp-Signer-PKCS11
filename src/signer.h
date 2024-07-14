#pragma once
#include <string>

struct evp_pkey_st;
struct x509_st;

namespace Signer
{
	//Returns the only the signature node. Signes the whole content of the given xml document.
	std::string getSignature(const std::string& xml, evp_pkey_st* prvKey, x509_st* cert, const std::string& refUri = "", bool XAdES = false);
	//Returns the given xml document plus enveloped signature node
	std::string signEnveloped(const std::string& xml, evp_pkey_st* prvKey, x509_st* cert, bool XAdES = false);
}