control 'SV-234677' do
  title 'The application must use FIPS-validated SHA-256 or higher hash function for digital signature generation and verification.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. 

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use only. 

Satisfies:FCS_COP.1.1(4)'
  desc 'check', 'Verify the UEM server uses FIPS-validated SHA-256 or higher hash function for digital signature generation and verification.

If the UEM server does not use FIPS-validated SHA-256 or higher hash function for digital signature generation and verification, this is a finding.'
  desc 'fix', 'Configure the UEM server to use FIPS-validated SHA-256 or higher hash function for digital signature generation and verification.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37862r616031_chk'
  tag severity: 'high'
  tag gid: 'V-234677'
  tag rid: 'SV-234677r879898_rule'
  tag stig_id: 'SRG-APP-000610-UEM-000402'
  tag gtitle: 'SRG-APP-000610'
  tag fix_id: 'F-37827r615666_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
