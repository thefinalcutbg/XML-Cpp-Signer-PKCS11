#include "Signer.h"

#include "freefn.h"
#include "pkcs11.h"

std::string Signer::signEnveloped(const std::string& xml, const PKCS11& pkcs11)
{
	std::string id = "id-28aac514ba01354d233a15f541909940";

	std::string xadesNode =
			"<xades:SignedProperties Id=\"xades-" + id + "\">"
					"<xades:SignedSignatureProperties>"
						"<xades:SigningTime>2024-07-11T13:57:37Z</xades:SigningTime>"
						"<xades:SigningCertificateV2>"
							"<xades:Cert>"
								"<xades:CertDigest>"
									"<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
									"<DigestValue>"
										+
											FreeFn::getSHA256DigestBase64(pkcs11.x509raw())
										+
								"</DigestValue>"
								"</xades:CertDigest>"
								"<xades:IssuerSerialV2>MIGIMHykejB4MQswCQYDVQQGEwJCRzEYMBYGA1UEYRMPTlRSQkctMjAxMjMwNDI2MRIwEAYDVQQKEwlCT1JJQ0EgQUQxEDAOBgNVBAsTB0ItVHJ1c3QxKTAnBgNVBAMTIEItVHJ1c3QgT3BlcmF0aW9uYWwgUXVhbGlmaWVkIENBAggMpUOaBGkKwg==</xades:IssuerSerialV2>"
							"</xades:Cert>"
						"</xades:SigningCertificateV2>"
						"<xades:SignatureProductionPlaceV2>"
							"<xades:City/>"
							"<xades:StateOrProvince/>"
							"<xades:PostalCode/>"
							"<xades:CountryName>BG</xades:CountryName>"
						"</xades:SignatureProductionPlaceV2>"
						"<xades:SignerRoleV2>"
							"<xades:ClaimedRoles>"
								"<xades:ClaimedRole>Signed By</xades:ClaimedRole>"
							"</xades:ClaimedRoles>"
						"</xades:SignerRoleV2>"
					"</xades:SignedSignatureProperties>"
					"<xades:SignedDataObjectProperties>"
						"<xades:DataObjectFormat ObjectReference=\"#refId123\">"
							"<xades:MimeType>text/xml</xades:MimeType>"
						"</xades:DataObjectFormat>"
					"</xades:SignedDataObjectProperties>"
				"</xades:SignedProperties>";

	const std::string signatureNs = "http://www.w3.org/2000/09/xmldsig#";

	std::string signedInfo =
    "<SignedInfo>"
		"<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
		"<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
		"<Reference Id=\"refId123\" URI=\"\">"
			"<Transforms>"
				"<Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">"
					"<XPath>not(ancestor-or-self::Signature)</XPath>"
				"</Transform>"
				"<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
			"</Transforms>"
			"<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
			"<DigestValue>"
				//digest value of the document
                +   
                FreeFn::base64Encode(
                    FreeFn::calculateSHA256Digest(
                        FreeFn::canonicalizeXML(xml)
                    )
                )
                +
          "</DigestValue>"
		    "</Reference>"
		"<Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xades-" + id + "\">"
			    "<Transforms>"
				    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
			    "</Transforms>"
			    "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
			    "<DigestValue>" 
                   //digest value of the Signed properties
				+
					FreeFn::base64Encode(
						FreeFn::calculateSHA256Digest(
							FreeFn::canonicalizeXML(
								FreeFn::addNamespacesToRoot(xadesNode, { {"xades", "http://uri.etsi.org/01903/v1.3.2#"}, {"", signatureNs } })
							)
						)
					)
                +
			"</DigestValue>"
		"</Reference>"
	"</SignedInfo>";

	
	std::string signature = 
		"<Signature xmlns=\""+ signatureNs + "\" Id=\"" + id +"\">" +
			signedInfo +
			"<SignatureValue Id=\"value-" + id + "\">" +
				FreeFn::calculateSignature(
						FreeFn::canonicalizeXML(
							FreeFn::addNamespacesToRoot( //since we use exclusive C14, only the signatureNs is required
								signedInfo, NSList{ { "", signatureNs} }
							)
					) ,pkcs11.takePrivateKey()
				)
			 +
			"</SignatureValue>" +
			"<KeyInfo><X509Data><X509Certificate>" +
				pkcs11.x509_base64() +
			"</X509Certificate></X509Data></KeyInfo>" +
			
			"<Object>"
		"<xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Target=\"#" + id + "\">" +
					xadesNode +
				"</xades:QualifyingProperties>"
			"</Object>"
		"</Signature>"
	;

	auto result = xml;

	int insertPosition = result.size() - 1;

	for (;
		result[insertPosition] != '<' &&
		insertPosition != 0;
		insertPosition--
		) {
	};

	if (!insertPosition) return "not an xml (no closing tag)";


	result.insert(insertPosition, signature);

	return result;
}
