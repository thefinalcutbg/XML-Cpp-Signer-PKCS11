#pragma once

#include <string>
#include <vector>

struct x509_st;
struct evp_pkey_st;

typedef std::vector<std::pair<std::string, std::string>> NSList;

//Some free functions using libxml2 for canonicalization and openssl for encryption

namespace FreeFn 
{
    // Canonicalizes XML using Exclusive canonicalization
    std::string canonicalizeXML(const std::string& xmlInput);
   
    std::string base64Encode(const std::string& input);

    // Function to calculate the SHA-256 digest
    std::string calculateSHA256Digest(const std::string& canonicalizedXML);

    //digests, calculates signature and returns it as base64
    std::string calculateSignature(const std::string& canonicalizedXml, evp_pkey_st* prv_handle);

    //digest of the X509 (required by XAdES)
    std::string getSHA256DigestBase64(x509_st* cert);
    
    // Converts x509 certificate to base64
    std::string IssuerSerialBase64(x509_st* cert);
   
    //checks if x509 is valid according to current datetime
    bool isValidX509(x509_st* cert);
    
    // Function to add namespaces as attributes to the root element
    std::string addNamespacesToRoot(const std::string& xmlContentSrc, const NSList& nsList);
    
    // Function to get namespaces from the root element in case of inclusive canonicalization
    NSList getNamespacesFromRoot(const std::string xml);

    // Get ISO8601 timestamp
    std::string get8601timestamp();

    // Get country code
    std::string get_country_from_x509(x509_st* cert);
}