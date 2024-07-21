# XML Cpp Signer PKCS11

A simple C++17 script that creates enveloped XML signature using the PKCS11 interface. It supports XAdES BASELINE_B specification.

- Verify XAdES at [EC DSS](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation) or at [https://verifysignature.eu](https://verifysignature.eu/verification/#dropzone)
- Verify XML DSig at [Chilkat XML Verifier](https://tools.chilkat.io/xmlDsigVerify.cshtml)

## Dependencies
- [OpenSsl](https://github.com/openssl/openssl)
- [Libp11](https://github.com/OpenSC/libp11)
- [LibXml2](https://github.com/GNOME/libxml2)

## Setup

Use the provided MS Visual Studio solution or setup the project by yourself. Provide the necessary includes and libs.

## Example
```
#include <iostream>
#include "signer.h"
#include "pkcs11.h"

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

          std::cout << "Enter password: ";
          std::cin >> password;
     
          if (!hsm.login(password)) {
              std::cout << std::endl << "Wrong password!" << std::endl;
              return 0;
          }
      }
     
      bool signWithXAdES = true;
      std::cout << std::endl << Signer::signEnveloped(xml, hsm.takePrivateKey(), hsm.x509raw(), signWithXAdES);
     
      return 0;
}
```

## License

This software is licensed under the MIT license.
