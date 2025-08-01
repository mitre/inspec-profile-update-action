control 'SV-240806' do
  title 'tc Server HORIZON must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when authenticating users and processes.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules. 

vRA relies upon the OpenSSL suite of encryption libraries. A special carefully defined software component called the OpenSSL FIPS Object Module has been created from the OpenSSL libraries to provide FIPS 140-2 validated encryption. This Module was designed for compatibility with OpenSSL so that products using the OpenSSL API can be converted to use validated cryptography with minimal effort.'
  desc 'check', %q(At the command prompt, execute the following command:

grep bio-ssl.cipher.list /opt/vmware/horizon/workspace/conf/catalina.properties

If the value of "bio-ssl.cipher.list" does not match the list of FIPS 140-2 ciphers or is missing, this is a finding.

Note: To view a list of FIPS 140-2 ciphers, at the command prompt execute the following command:

openssl ciphers 'FIPS')
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/catalina.properties.

Navigate to and locate "bio-ssl.cipher.list".

Configure the "bio-ssl.cipher.list" with FIPS 140-2 compliant ciphers.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44039r674435_chk'
  tag severity: 'medium'
  tag gid: 'V-240806'
  tag rid: 'SV-240806r674436_rule'
  tag stig_id: 'VRAU-TC-000460'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag fix_id: 'F-43998r674161_fix'
  tag 'documentable'
  tag legacy: ['SV-100693', 'V-90043']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
