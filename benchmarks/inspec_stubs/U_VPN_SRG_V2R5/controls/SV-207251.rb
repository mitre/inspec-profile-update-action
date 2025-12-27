control 'SV-207251' do
  title 'The IPsec VPN Gateway IKE must use NIST FIPS-validated cryptography to implement encryption services for unclassified VPN traffic.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VPN gateway must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the IPsec VPN Gateway IKE uses a NIST FIPS-validated cryptography to implement encryption services for unclassified VPN traffic.

If the IPsec VPN Gateway IKE does not use NIST FIPS-validated cryptography to implement encryption services for unclassified VPN traffic, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway IKE to use NIST FIPS-validated cryptography to implement encryption services for unclassified VPN traffic.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7511r378374_chk'
  tag severity: 'medium'
  tag gid: 'V-207251'
  tag rid: 'SV-207251r856724_rule'
  tag stig_id: 'SRG-NET-000510-VPN-002180'
  tag gtitle: 'SRG-NET-000510'
  tag fix_id: 'F-7511r378375_fix'
  tag 'documentable'
  tag legacy: ['V-97197', 'SV-106335']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
