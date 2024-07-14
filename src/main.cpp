#include <string>
#include <iostream>
#include "signer.h"
#include "pkcs11.h"
#include "freefn.h"

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

    std::cout << Signer::signEnveloped(xml, hsm, true);
    return 0;
}
