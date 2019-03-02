# windows-pe-signature-verifying

## Brief
Library that used to verify PE files signatures and get certificate info

## Projects
**command-line-tool**  <br />
**pe-signature-utils**  <br />
**tests**  <br />

## Links
[WinVerifyTrust](https://docs.microsoft.com/en-us/windows/desktop/api/wintrust/nf-wintrust-winverifytrust) <br />
[Certificate and Trust return values](https://docs.microsoft.com/en-us/windows/desktop/seccrypto/certificate-and-trust-return-values)  <br />
[Windows 8 and 10 signature hash algorithm](https://stackoverflow.com/questions/26216789/getting-digital-signature-from-mmc-exe-at-windows-8)  <br />
[Forum discussion about PE signature info](http://qaru.site/questions/7338503/amended-code-to-retrieve-dual-signature-information-from-pe-executable-in-windows)  <br />


## Usage

### command-line-tool

Example usage:  <br />
&nbsp;&nbsp;`command-line-tool.exe "C:\\Program Files\\Mozilla Firefox\\firefox.exe"`

Example output: <br />
&nbsp;&nbsp;`File name: C:\Program Files\Mozilla Firefox\firefox.exe` <br />
&nbsp;&nbsp;`Verified: Signed` <br />
&nbsp;&nbsp;`SHA256: 7AF330A6446D56457BA9E90FFF0418A589E26385566BD7AF8F28578E3210C553` <br />
&nbsp;&nbsp;`Serial number: 0c5396dcb2949c70fac48ab08a07338e` <br />
&nbsp;&nbsp;`Issuer name: DigiCert SHA2 Assured ID Code Signing CA` <br />
&nbsp;&nbsp;`Subject name: Mozilla Corporation` <br />
&nbsp;&nbsp;`Signing algorithm: sha256RSA` <br />
&nbsp;&nbsp;`Signing date: 08/01/2019 10:01` <br />

### pe-signature-utils
&nbsp;&nbsp;Generates static library.  <br />
&nbsp;&nbsp;The public API is specified in **src/PeSignatureVerifier.h** header.<br />

### tests
&nbsp;&nbsp;Generates binary of tests for pe-signature-utils. <br />

## Todos
Dual signatures


