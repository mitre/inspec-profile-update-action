control 'SV-233285' do
  title 'The container platform must use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).'
  desc 'Without the use of digital signature, information can be altered by unauthorized accounts accessing or modifying the container platform registry, keystore, and container at runtime. Digital signatures provide non-repudiation for transactions between the components within the container platform. Without the use of approved FIPS-validated SHA-2 or higher hash function with digital signatures, the container platform cannot claim the validity of the individual or service identity and guarantee private key is kept secret. Keeping the private keys secure is vital for validating individuals or service identity prior to information exchange. The container platform must be configured to use SHA-2 or higher hash functions for digital signatures in accordance with SP 800-131Ar2.'
  desc 'check', 'Review the container platform configuration to validate that a FIPS-validated SHA-2 or higher hash function is being used for digital signature generation and verification. 

If a FIPS-validated SHA-2 or higher hash function is not being used for digital signature generation and verification, this is a finding.'
  desc 'fix', 'Configure the container platform to use a FIPS-validated SHA-2 or higher hash function for digital signature generation and verification.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36221r601857_chk'
  tag severity: 'medium'
  tag gid: 'V-233285'
  tag rid: 'SV-233285r879898_rule'
  tag stig_id: 'SRG-APP-000610-CTR-001385'
  tag gtitle: 'SRG-APP-000610'
  tag fix_id: 'F-36189r601343_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
