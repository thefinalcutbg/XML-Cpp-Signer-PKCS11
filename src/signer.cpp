#include "Signer.h"

#include "freefn.h"
#include "pkcs11.h"
#include <iostream>

std::string Signer::signEnveloped(const std::string& xml, const PKCS11& pkcs11)
{
	/*
	std::string xadesNode =
		R"xml(<xades:SignedProperties Id="signedProperties">
					<xades:SignedSignatureProperties>
						<xades:SigningTime>2024-07-11T13:57:37Z</xades:SigningTime>
						<xades:SigningCertificateV2>
							<xades:Cert>
								<xades:CertDigest>
									<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
									<DigestValue>)xml"
										+
											FreeFn::getSHA256DigestBase64(pkcs11.x509raw())
										+
							  R"xml(</DigestValue>
								</xades:CertDigest>
							</xades:Cert>
						</xades:SigningCertificateV2>
						<xades:SignatureProductionPlaceV2>
							<xades:City/>
							<xades:StateOrProvince/>
							<xades:PostalCode/>
							<xades:CountryName>BG</xades:CountryName>
						</xades:SignatureProductionPlaceV2>
						<xades:SignerRoleV2>
							<xades:ClaimedRoles>
								<xades:ClaimedRole>Signed By</xades:ClaimedRole>
							</xades:ClaimedRoles>
						</xades:SignerRoleV2>
					</xades:SignedSignatureProperties>
					<xades:SignedDataObjectProperties>
						<xades:DataObjectFormat ObjectReference="#r-id-1">
							<xades:MimeType>text/xml</xades:MimeType>
						</xades:DataObjectFormat>
					</xades:SignedDataObjectProperties>
				</xades:SignedProperties>)xml";
*/

	std::string signedInfo =
    "<SignedInfo>"
		"<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
		"<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
		"<Reference URI=\"\">"
			"<Transforms>"
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
	/*
        R"xml(</DigestValue>
		    </Reference>
		    <Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#signedProperties">
			    <Transforms>
				    <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			    </Transforms>
			    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
			    <DigestValue>)xml" 
                   //digest value of the Signed properties
				+
					FreeFn::base64Encode(
						FreeFn::calculateSHA256Digest(
							FreeFn::canonicalizeXML(
								FreeFn::addNamespacesToRoot(xadesNode, xadesNs)
							)
						)
					)
                +
				*/
		"</DigestValue>"
			"</Reference>"
				"</SignedInfo>";

	std::string signatureNs = "http://www.w3.org/2000/09/xmldsig#";

	std::string signature = 
		"<Signature xmlns=\""+ signatureNs + "\">" +
			signedInfo +
			"<SignatureValue>" +
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
			
		//	"<Object>"
		//		"<xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Target=\"#id-signature\">" +
		//			xadesNode +
	//			"</xades:QualifyingProperties>"
	//		"</Object>"
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
