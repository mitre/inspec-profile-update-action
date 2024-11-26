control 'SV-239953' do
  title 'The Cisco ASA must be configured to use NIST FIPS-validated cryptography for Internet Key Exchange (IKE) Phase 1.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VPN gateway must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the ASA uses a NIST FIPS-validated cryptography for IKE Phase 1 as shown in the example below.

crypto ikev2 policy 1
 encryption aes-256

If the ASA is not configured to use NIST FIPS-validated cryptography for IKE Phase 1, this is a finding.'
  desc 'fix', 'Configure the ASA to use NIST FIPS-validated cryptography for IKE Phase 1.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# encryption aes-256'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43186r916120_chk'
  tag severity: 'medium'
  tag gid: 'V-239953'
  tag rid: 'SV-239953r916122_rule'
  tag stig_id: 'CASA-VN-000170'
  tag gtitle: 'SRG-NET-000510-VPN-002180'
  tag fix_id: 'F-43145r916121_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
