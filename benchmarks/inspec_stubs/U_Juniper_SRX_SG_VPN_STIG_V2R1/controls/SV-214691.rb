control 'SV-214691' do
  title 'The Juniper SRX Services Gateway VPN IKE must use NIST FIPS-validated cryptography to implement encryption services for unclassified VPN traffic.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify all Internet Key Exchange (IKE) proposals are set to use the AES encryption algorithm.

[edit]
show security ike

View the value of the encryption algorithm for each defined proposal.

If the value of the authentication method and other options are not set to use FIPS-compliant values, this is a finding.'
  desc 'fix', 'The following example commands configure the IKE (phase 1) proposal.

[edit]
set security ike proposal <P1-PROPOSAL> authentication-method rsa-signatures
set security ike proposal p1-proposal dh-group group14
set security ike proposal p1-proposal authentication-algorithm sha-256
set security ike proposal p1-proposal encryption-algorithm aes-256-cbc
set security ike proposal p1-proposal lifetime-seconds 86400'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15892r297660_chk'
  tag severity: 'medium'
  tag gid: 'V-214691'
  tag rid: 'SV-214691r383878_rule'
  tag stig_id: 'JUSX-VN-000024'
  tag gtitle: 'SRG-NET-000510'
  tag fix_id: 'F-15890r297661_fix'
  tag 'documentable'
  tag legacy: ['V-66671', 'SV-81161']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
