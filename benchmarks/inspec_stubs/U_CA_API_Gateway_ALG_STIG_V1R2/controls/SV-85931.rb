control 'SV-85931' do
  title 'The CA API Gateway that stores secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

Private key data associated with software certificates, including those issued to an ALG, is required to be generated and protected in at least a FIPS 140-2 Level 1 validated cryptographic module.

By default, the CA API Gateway uses the SunJSSE PKCS#12 for key storage, which is not approved at FIPS 140-2. The Gateway must be configured to use a SafeNet Luna Hardware Security Module (HSM) that is approved at FIPS-140-2 Level 3."
  desc 'check', 'Verify an HSM, such as the SafeNet Luna HSM, is currently storing Private Keys. 

If an HSM is not present, this is a finding.'
  desc 'fix', 'Refer to the “CA API Management Documentation Wiki" at https://wiki.ca.com/display/GATEWAY90/CA+API+Gateway+Home for directions on configuring the CA API Gateway to use a SafeNet Luna HSM for secure private key storage.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71307'
  tag rid: 'SV-85931r1_rule'
  tag stig_id: 'CAGW-GW-000180'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-77617r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
