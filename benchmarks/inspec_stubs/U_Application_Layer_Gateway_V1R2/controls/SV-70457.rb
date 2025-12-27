control 'SV-70457' do
  title 'The ALG that stores secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

Private key data associated with software certificates, including those issued to an ALG, is required to be generated and protected in at least a FIPS 140-2 Level 1 validated cryptographic module."
  desc 'check', 'If the ALG does not generate or store secret or private keys, this is not applicable.

Verify the ALG uses a FIPS 140-2 validated cryptographic module for private key generation, storage and access. 

If the ALG does not use or support a FIPS 140-2 validated cryptographic module for producing, storing and accessing private key data, this is a finding.'
  desc 'fix', 'For ALGs that store secret or private keys, configure the ALG settings to ensure it uses a FIPS 140-2 validated cryptographic module for generating, storing and accessing private keys.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56203'
  tag rid: 'SV-70457r1_rule'
  tag stig_id: 'SRG-NET-000062-ALG-000092'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-61079r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
