control 'SV-79715' do
  title 'The DataPower Gateway that provides intermediary services for TLS must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 

Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', "Using the WebGUI, go to Objects >> Crypto Configuration >> SSL Client Profile and SSL Server Profile. 

Confirm that each Profile's parameters are set correctly (as defined in the Fix column) and that each profile is using a correctly defined Crypto Validation Credentials (as defined in the Fix column). 

If they are not correctly defined, this is a finding."
  desc 'fix', 'Objects >> Crypto Configuration >> Crypto Validation Credentials >> Press add to create a credential. Supply the following parameters:

Name: Assign a name to these Crypto Validation Credentials

Certificates: Define the certificate aliases for the Crypto Validation Credentials object. Each certificate in the Validation Credentials object is the certificate that a TLS peer might send or is the certificate of the Certification Authority (CA) that signed the certificate sent by a peer or is the root certificate.

Certificate Validation Mode: Select "Full certificate chain checking (PKIX)".

Use CRL: On

Require CRL: On

CRL Distribution Points Handling: Require. 
Specifying this option will result in checks against, but does not fetch, the CRLs in the X.509 CRL Distribution Point extensions. If any CRL in a CRL Distribution Point extension no longer exists in the CRL cache, the certificate validation fails.

USE THE ABOVE-DEFINED CRYPTO-VALIDATION CREDENTIALS FOR TLS PATH VALIDATION.

SSL CLIENT PROFILE
Using the WebGUI, go to Objects >> Crypto Configuration >> SSL Client Profile. Supply the following parameters:

Protocols: Check only TLS versions 1.1 and 1.2

Validate server certificate: On

Validation credentials: Select from the dropdown the above-defined Crypto Validation Credentials

SSL SERVER PROFILE
Using the WebGUI, go to Objects >> Crypto Configuration >> SSL Server Profile. Supply the following parameters:

Protocols: Check only TLS versions 1.1 and 1.2

Request client authentication: On

Require client authentication: On

Validate client certificate: On

Send client authentication CA list: On

Validation credentials: Select from the dropdown the above-defined Crypto Validation Credentials.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65225'
  tag rid: 'SV-79715r1_rule'
  tag stig_id: 'WSDP-AG-000042'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-71165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
