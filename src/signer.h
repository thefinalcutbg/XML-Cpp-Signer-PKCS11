#pragma once
#include <string>

struct x509_st;
struct evp_pkey_st;

namespace Signer
{
	std::string signEnveloped(const std::string& xml, evp_pkey_st* pkey, x509_st* cert, bool XAdES = false);
}