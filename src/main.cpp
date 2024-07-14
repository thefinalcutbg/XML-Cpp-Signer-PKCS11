#include <string>
#include <iostream>
#include "signer.h"
#include "pkcs11.h"
#include "freefn.h"

//Simple example. If you want to use the code in your software, don't include this file 

int main()
{
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

    //Enveloped signature XAdES example:
    std::string xml = R"xml(<?xml version="1.0"?><example>some data to sign</example>)xml";

    std::cout << Signer::signEnveloped(xml, hsm.takePrivateKey(), hsm.x509raw(), true) << "\n\n\n\n";
    
    //Signing part of xml (e.g. a body of a SOAP message)
    std::string body = R"(<e:Body Id="signedContent">some contents</e:Body>)";

    std::string soap =
        R"(<?xml version="1.0" encoding="utf-8"?><e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/"><e:Header>)"
        + Signer::getSignature(
            FreeFn::addNamespacesToRoot(body, { {"e", "http://schemas.xmlsoap.org/soap/envelope/" } }), 
            hsm.takePrivateKey(), 
            hsm.x509raw(), 
            "#signedContent", 
            false)
        + "</e:Header>"
        + body +
        "</e:Envelope>"
        ;

    std::cout << soap;

    return 0;
}
