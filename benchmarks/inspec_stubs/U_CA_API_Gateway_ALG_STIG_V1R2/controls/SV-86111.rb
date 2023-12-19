control 'SV-86111' do
  title 'The CA API Gateway providing encryption intermediary services must use NIST FIPS-validated cryptography to implement encryption services.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).

Encryption operations are performed in the following assertions: "Encrypt XML Element" and "Encrypt Element". Any of the listed encryption methods (AES 128 CBC, AES 192 CBC, AES 128 GCM, AES 256 GCM, Triple DES) included with the Assertions are NIST-FIPS validated. The FIPS-140-2 Certified RSA BSAFE Crypto-J Module is used for encryption operations. All CA API Gateway references to Triple-DES directly imply three-key and NOT two-key.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click each of the Registered Services that requires NIST-FIPS validated encryption services. 

Verify that the "Encrypt XML Element" or "Encrypt Element" Assertion has/have been added to the policy in accordance with organizational requirements. 

If the Assertion(s) is/are not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click each of the Registered Services that require NIST-FIPS validated encryption services. 

Add the "Encrypt XML Element" and/or "Encrypt Element" to the policy and configure in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71487'
  tag rid: 'SV-86111r1_rule'
  tag stig_id: 'CAGW-GW-000900'
  tag gtitle: 'SRG-NET-000510-ALG-000111'
  tag fix_id: 'F-77807r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
