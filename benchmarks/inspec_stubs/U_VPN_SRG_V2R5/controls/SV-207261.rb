control 'SV-207261' do
  title 'The VPN remote access server must be configured use cryptographic algorithms approved by NSA to protect NSS for remote access to a classified network.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VPN gateway must implement cryptographic modules adhering to the higher standards approved by the Federal Government since this provides assurance they have been tested and validated.

NIST cryptographic algorithms approved by NSA to protect NSS. Based on an analysis of the impact of quantum computing, cryptographic algorithms specified by CNSSP-15 and approved for use in products in the CSfC program, the approved algorithms have been changed to more stringent protocols configure with increased bit sizes and other secure characteristics to protect against quantum computing threats. The Commercial National Security Algorithm Suite (CNSA Suite) replaces Suite B.'
  desc 'check', 'Verify the VPN gateway is configured to use cryptography that is compliant with NSA/CSS parameters to protect NSS for remote access to a classified network.

If the VPN gateway is not configured to use cryptography that is compliant with NSA/CSS parameters to protect NSS for remote access to a classified network, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use cryptography that is compliant with NSA/CSS parameters to protect NSS for remote access to a classified network.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7521r803440_chk'
  tag severity: 'high'
  tag gid: 'V-207261'
  tag rid: 'SV-207261r878134_rule'
  tag stig_id: 'SRG-NET-000565-VPN-002390'
  tag gtitle: 'SRG-NET-000565'
  tag fix_id: 'F-7521r803441_fix'
  tag 'documentable'
  tag legacy: ['SV-106355', 'V-97217']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
