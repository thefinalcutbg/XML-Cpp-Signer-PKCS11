#include <string>
#include <iostream>
#include "signer.h"
#include "pkcs11.h"
#include "crypto.h"

//Simple example. If you want to use the code in your software, don't include this file 

int main()
{
    std::string xml = R"xml(<?xml version="1.0"?><example>some data to sign</example>)xml";

    PKCS11::setMiddlewareFilePath({ "C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll" });

    PKCS11 hsm;

    if (!hsm.hsmLoaded()) {
        std::cout << "no hsm found";
        return 0;
    }

    if (hsm.loginRequired()) {

        std::string password;

       // password = "";
        std::cout << "Enter password: ";
        std::cin >> password;

        if (!hsm.login(password)) {
            std::cout << std::endl << "Wrong password!" << std::endl;
        }
    }

    //Sign XAdES enveloped example
    std::cout << std::endl << Signer::signEnveloped(xml, hsm.takePrivateKey(), hsm.x509raw(), true) << "\n\n\n\n";

    //Sign SOAP message body

    std::string body = R"(<e:Body id="signedContent"><ns3:query xmlns:ns1="http://pis.technologica.com/views/" xmlns:ns3="http://pis.technologica.com/ws/"><ns3:user><ns3:egn>8903261129</ns3:egn></ns3:user><ns3:from_clause>INYEAR_DENTAL_ACTS</ns3:from_clause><ns3:orderby_clause><ns1:ocolumn sort="DESC">ACTIVITY_DATE</ns1:ocolumn></ns3:orderby_clause></ns3:query></e:Body>)";

    std::string signedSoap = R"(<?xml version="1.0" encoding="utf-8"?><e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/"><e:Header>)";

    signedSoap += Signer::getSignature(
        //setting envelope namespace
        Crypto::addNamespacesToRoot(body, { {"e", "http://schemas.xmlsoap.org/soap/envelope/"} }),
        hsm.takePrivateKey(),
        hsm.x509raw(),
        "#signedContent",
        true
    );

    signedSoap += "</e:Header>";

    signedSoap += body;

    signedSoap += "</e:Envelope>";

    std::cout << signedSoap;

    return 0;
}
