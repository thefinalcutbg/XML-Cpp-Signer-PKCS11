#include "pkcs11.h"

#include <libp11/libp11.h>
#include <vector>
#include <filesystem>

#include "freefn.h"

PKCS11_CTX* ctx{ nullptr };
unsigned int nslots{ 0 };
PKCS11_slot_st* pslots{ nullptr };
PKCS11_slot_st* current_slot{ nullptr };


void PKCS11::setMiddlewareFilePath(const std::vector<std::string>& filePaths)
{
	middlewarePaths = filePaths;
}

PKCS11::PKCS11()
{
	if (!ctx) {
		ctx = PKCS11_CTX_new();
	}

	for (auto& middleware : middlewarePaths)
	{
		if (!std::filesystem::exists(middleware)) continue;

		if (PKCS11_CTX_load(ctx, middleware.data()) == -1) continue;

		if (PKCS11_enumerate_slots(ctx, &pslots, &nslots) == -1)  continue;

		current_slot = PKCS11_find_token(ctx, pslots, nslots);

		if (current_slot == nullptr) continue;

		PKCS11_cert_st* certs{ nullptr };
		unsigned int ncerts{ 0 };

		PKCS11_enumerate_certs(current_slot->token, &certs, &ncerts);

		//finding a valid certificate
		if (ncerts == 0) continue;

		for (int i = 0; i < ncerts; i++)
		{
			m_certificate = &certs[i];

			if (FreeFn::isValidX509(m_certificate->x509)) break;
		}

		if (m_certificate) {
			break;
		}

	}

	if (m_certificate == nullptr) return;

	int length = i2d_X509(m_certificate->x509, 0);

	std::vector<char> vec;
	vec.resize(length);
	char* data = vec.data();

	char** dataP = &data;
	unsigned char** dataPu = (unsigned char**)dataP;

	if (i2d_X509(m_certificate->x509, dataPu) < 0)
	{
		m_509b64 = std::string();
		return;
	}

	m_509b64 = FreeFn::base64Encode(std::string(vec.data(), vec.size()));

	auto key = PKCS11_find_key(m_certificate);

	if (key) m_prv_key = PKCS11_get_private_key(key);
}

bool PKCS11::hsmLoaded()
{
	return m_certificate != nullptr;
}

bool PKCS11::loginRequired()
{
	return m_prv_key == nullptr;
}

bool PKCS11::login(const std::string& pass)
{
	if (!loginRequired()) return true;

	bool success = PKCS11_login(current_slot, 0, pass.data()) == 0;

	if (success) {
		m_prv_key = PKCS11_get_private_key(PKCS11_find_key(m_certificate));
	}

	return success;
}

const std::string& PKCS11::pem_x509cert() const
{
	return "-----BEGIN CERTIFICATE-----\n" + m_509b64 + "\n-----END CERTIFICATE-----";
}

evp_pkey_st* PKCS11::takePrivateKey() const
{
	return m_prv_key;
}

x509_st* PKCS11::x509raw() const
{
	return m_certificate->x509;
}

void PKCS11::cleanup()
{
	if (nslots) {
		PKCS11_release_all_slots(ctx, pslots, nslots);
		nslots = 0;
		pslots = 0;
	}

	current_slot = nullptr;

	if (ctx)
	{
		PKCS11_CTX_unload(ctx);
	}
}

PKCS11::~PKCS11()
{
	//PKCS11_release_all_slots(ctx, m_slots, nslots);
}
