control 'SV-254803' do
  title 'The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect classified data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.
 
Advanced Encryption Standard (AES)
Symmetric block cipher used for information protection
FIPS Pub 197
Use 256 bit keys to protect up to TOP SECRET

Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
Asymmetric algorithm used for key establishment
NIST SP 800-56A
Use Curve P-384 to protect up to TOP SECRET.

Elliptic Curve Digital Signature Algorithm (ECDSA)
Asymmetric algorithm used for digital signatures
FIPS Pub 186-4
Use Curve P-384 to protect up to TOP SECRET.

Secure Hash Algorithm (SHA)
Algorithm used for computing a condensed representation of information
FIPS Pub 180-4

Use SHA-384 to protect up to TOP SECRET.
 
Diffie-Hellman (DH) Key Exchange
Asymmetric algorithm used for key establishment
IETF RFC 3526 
Minimum 3072-bit modulus to protect up to TOP SECRET

RSA
Asymmetric algorithm used for key establishment
NIST SP 800-56B rev 1
Minimum 3072-bit modulus to protect up to TOP SECRET

RSA 
Asymmetric algorithm used for digital signatures
FIPS PUB 186-4
Minimum 3072 bit-modulus to protect up to TOP SECRET.'
  desc 'check', 'Review the application documentation, system security plan and interview the application administrator to determine if the application processes classified data.

If the application does not process classified data, this requirement is not applicable.

Identify the data classifications and the cryptographic protections established to protect the application data.

Verify the application is configured to utilize the appropriate encryption based upon data classification, cryptographic tasks that need to be performed (information protection, hashing, signing) and information protection requirements.

NIST-certified cryptography must be used to store classified non-Sources and Methods Intelligence (SAMI) information if required by the information owner.

NSA-validated type-1 encryption must be used for all SAMI data stored in the enclave.

If the application is not configured to utilize the NSA-approved cryptographic modules in accordance with data protection requirements specified in the security plan, this is a finding.'
  desc 'fix', 'Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24239r588004_chk'
  tag severity: 'medium'
  tag gid: 'V-254803'
  tag rid: 'SV-254803r865217_rule'
  tag stig_id: 'APSC-DV-002010'
  tag gtitle: 'APSC-DV-002010'
  tag fix_id: 'F-24228r588005_fix'
  tag 'documentable'
  tag legacy: ['SV-84811', 'V-70189']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
