#pragma once
#include "freefn.h"

#include <ctime>

#include <libxml/parser.h>
#include <libxml/c14n.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

std::string FreeFn::canonicalizeXML(const std::string& xmlInput)
{

        // Parse the XML from the input string
        xmlDocPtr doc = xmlReadMemory(xmlInput.c_str(), xmlInput.size(), "noname.xml", NULL, XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == nullptr) {
        return "Error parsing XML";
    }
   
    xmlChar* canonicalBuffer = nullptr;
    int bufferSize = 0;

    // Canonicalize the XML document or the specified element
    int result = xmlC14NDocDumpMemory(doc, nullptr, XML_C14N_EXCLUSIVE_1_0, nullptr, 0, &canonicalBuffer);

    if (result < 0) {
        xmlFreeDoc(doc);

        return "Error canonicalizing XML";
    }

    // Create a std::string from the canonicalized output
    std::string canonicalizedXML((char*)canonicalBuffer, result);

    // Free the canonicalization buffer and the document
    xmlFree(canonicalBuffer);
    xmlFreeDoc(doc);

    // Cleanup function for the XML library
    xmlCleanupParser();

    return canonicalizedXML;
}

std::string FreeFn::base64Encode(const std::string& input) {

    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Disable newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string base64Encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return base64Encoded;
}


std::string FreeFn::calculateSHA256Digest(const std::string& canonicalizedXML) {

    // Buffer to hold the hash value
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Calculate the SHA-256 hash
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, canonicalizedXML.c_str(), canonicalizedXML.size());
    SHA256_Final(hash, &sha256);

    // Convert the hash to a string
    std::string digest(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
    return digest;
}

std::string FreeFn::calculateSignature(const std::string& signedInfo, evp_pkey_st* pkey)
{
     if (!pkey) {
        return std::string();
    }

    unsigned char* EncMsg{ nullptr };
    size_t MsgLenEnc{ 0 };


    EVP_MD_CTX* signCtx = EVP_MD_CTX_create();

    if (EVP_DigestSignInit(signCtx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_destroy(signCtx);
        return std::string();
    }
    if (EVP_DigestSignUpdate(signCtx, signedInfo.c_str(), signedInfo.size()) <= 0) {
        EVP_MD_CTX_destroy(signCtx);
        return std::string();
    }
    if (EVP_DigestSignFinal(signCtx, NULL, &MsgLenEnc) <= 0) {
        EVP_MD_CTX_destroy(signCtx);
        return std::string();
    }
    EncMsg = (unsigned char*)malloc(MsgLenEnc);
    if (EVP_DigestSignFinal(signCtx, EncMsg, &MsgLenEnc) <= 0) {
        EVP_MD_CTX_destroy(signCtx);
        return std::string();
    }
    EVP_MD_CTX_destroy(signCtx);

    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, EncMsg, MsgLenEnc);
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string encoded_data(buffer_ptr->data, buffer_ptr->length);

    BIO_free_all(bio);
    return encoded_data;
}

std::string FreeFn::getSHA256DigestBase64(x509_st* cert)
{
    // Check if the certificate is valid
    if (cert == nullptr) {
        return "Null certificate provided";
    }

    // Buffer to hold the DER encoded certificate
    unsigned char* derBuffer = nullptr;
    int derLength = i2d_X509(cert, &derBuffer);
    if (derLength < 0) {
        return "Failed to encode certificate to DER format";
    }

    // Compute the SHA256 digest
    unsigned char sha256Digest[SHA256_DIGEST_LENGTH];
    if (!SHA256(derBuffer, derLength, sha256Digest)) {
        OPENSSL_free(derBuffer);
        return "Failed to compute SHA256 digest";
    }

    // Encode the digest in base64
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, sha256Digest, SHA256_DIGEST_LENGTH);
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    // Copy the base64 encoded string to a std::string
    std::string base64Digest(bufferPtr->data, bufferPtr->length);

    // Clean up
    OPENSSL_free(derBuffer);
    BIO_free_all(bio);

    return base64Digest;
}

std::string FreeFn::IssuerSerialBase64(x509_st* cert)
{
    if (cert == nullptr) {
        return "Invalid X509 certificate provided";
    }

    // Get the serial number from the certificate
    ASN1_INTEGER* serialNumber = X509_get_serialNumber(cert);
    if (serialNumber == nullptr) {
        return "Failed to get serial number from certificate";
    }

    // Convert serial number to a string
    BIGNUM* bn = ASN1_INTEGER_to_BN(serialNumber, nullptr);
    if (bn == nullptr) {
        return "Failed to convert serial number to BIGNUM";
    }
    char* serialNumberHex = BN_bn2hex(bn);
    if (serialNumberHex == nullptr) {
        BN_free(bn);
        return "Failed to convert serial number to hex string";
    }
    std::string serialNumberStr(serialNumberHex);
    OPENSSL_free(serialNumberHex);
    BN_free(bn);

    // Convert the serial number string to Base64
    std::string serialNumberBase64 = base64Encode(serialNumberStr);

    return serialNumberBase64;
}


bool FreeFn::isValidX509(x509_st* cert)
{
    if (!cert) {
        return "Invalid certificate";
    }

    // Check the certificate's validity period
    time_t currentTime = time(nullptr);
    if (X509_cmp_time(X509_get0_notBefore(cert), &currentTime) > 0) {
        return false; // Certificate is not yet valid
    }
    if (X509_cmp_time(X509_get0_notAfter(cert), &currentTime) < 0) {
        return false; // Certificate has expired
    }

    // Verify the certificate's signature
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        return false; // Error getting public key
    }

    int ret = X509_verify(cert, pubkey);
    EVP_PKEY_free(pubkey);

    if (ret <= 0) {
        return false; // Certificate signature verification failed
    }

    return true; // Certificate is valid
    
}

std::vector<std::pair<std::string, std::string>> getNamespacesFromRoot(xmlNodePtr root) {
    std::vector<std::pair<std::string, std::string>> namespaces;

    for (xmlNsPtr ns = root->nsDef; ns != NULL; ns = ns->next) {
        std::string prefix = ns->prefix ? (char*)ns->prefix : "";
        std::string href = (char*)ns->href;
        namespaces.emplace_back(prefix, href);
    }

    return namespaces;
}

void customErrorHandler(void* ctx, const char* msg, ...) {(void)ctx;(void)msg;}

std::string FreeFn::addNamespacesToRoot(const std::string& xmlContentDst, const NSList& namespaces)
{
    //supress the missing namespace errors
     xmlSetGenericErrorFunc(NULL, customErrorHandler);

    // Parse the destination XML content
    xmlDocPtr docDst = xmlReadMemory(xmlContentDst.c_str(), xmlContentDst.size(), "noname.xml", NULL, 0);
    if (docDst == NULL) {
        return "Failed to parse destination document";
    }

    // Get the root element of the destination document
    xmlNodePtr rootDst = xmlDocGetRootElement(docDst);
    if (rootDst == NULL) {
        xmlFreeDoc(docDst);
        return "Failed to get root element of destination document";
    }

    // Add the namespaces as attributes to the root element of the destination document
    for (const auto& ns : namespaces) {
        std::string attrName = ns.first.empty() ? "xmlns" : "xmlns:" + ns.first;
        xmlNewNs(rootDst, BAD_CAST ns.second.c_str(), ns.first.size() ? BAD_CAST ns.first.c_str() : NULL);
    }

    // Convert the modified destination document back to a string
    xmlChar* xmlBuffer = NULL;
    int bufferSize = 0;
    xmlDocDumpFormatMemory(docDst, &xmlBuffer, &bufferSize, 1);

    // Create a std::string from the xmlBuffer
    std::string modifiedXml((char*)xmlBuffer, bufferSize);

    // Cleanup
    xmlFree(xmlBuffer);
    xmlFreeDoc(docDst);
    xmlCleanupParser();

    return modifiedXml;
}

std::vector<std::pair<std::string, std::string>> FreeFn::getNamespacesFromRoot(const std::string xml)
{

        // Parse the source XML content
        xmlDocPtr docSrc = xmlReadMemory(xml.c_str(), xml.size(), "noname.xml", NULL, 0);
    if (docSrc == NULL) {
        return {};
    }

    // Get the root element of the source document
    xmlNodePtr rootSrc = xmlDocGetRootElement(docSrc);
    if (rootSrc == NULL) {
        xmlFreeDoc(docSrc);
        return {};
    }

    std::vector<std::pair<std::string, std::string>> namespaces;

    for (xmlNsPtr ns = rootSrc->nsDef; ns != NULL; ns = ns->next) {
        std::string prefix = ns->prefix ? (char*)ns->prefix : "";
        std::string href = (char*)ns->href;
        namespaces.emplace_back(prefix, href);
    }

    return namespaces;
}

std::string FreeFn::get_country_from_x509(x509_st* cert)
{
    if (cert == NULL) {
        return "";
    }

    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (subject_name == NULL) {
        return "";
    }

    int country_index = X509_NAME_get_index_by_NID(subject_name, NID_countryName, -1);
    if (country_index < 0) {
        return "";
    }

    X509_NAME_ENTRY* country_entry = X509_NAME_get_entry(subject_name, country_index);
    if (country_entry == NULL) {
        return "";
    }

    ASN1_STRING* country_asn1 = X509_NAME_ENTRY_get_data(country_entry);
    if (country_asn1 == NULL) {
        return "";
    }

    unsigned char* country_str = NULL;
    int length = ASN1_STRING_to_UTF8(&country_str, country_asn1);
    if (length < 0) {
        return "";
    }

    std::string country((char*)country_str, length);
    OPENSSL_free(country_str);

    return country;
}

std::string FreeFn::get8601timestamp()
{
    time_t now;
    time(&now);
    char buf[21];
    strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));

    return std::string(buf);
}
