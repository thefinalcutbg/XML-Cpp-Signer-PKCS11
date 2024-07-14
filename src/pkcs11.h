#include <string>
#include <vector>

struct evp_pkey_st;
struct x509_st;
struct PKCS11_cert_st;

//A simple c++ wrapper around libp11

class PKCS11
{
	PKCS11_cert_st* m_certificate{ nullptr };
	std::string m_509b64;
	evp_pkey_st* m_prv_key{ nullptr };

	static inline std::vector<std::string> middlewarePaths;

public:

	static void setMiddlewareFilePath(const std::vector<std::string>& filePaths);

	PKCS11();
	bool hsmLoaded();

	bool loginRequired();
	bool login(const std::string& pass);
	const std::string& pem_x509cert() const;
	const std::string& x509_base64() const { return m_509b64; }
	evp_pkey_st* takePrivateKey() const;
	x509_st* x509raw() const;

	static void cleanup();

	~PKCS11();

};


