control 'SV-207262' do
  title 'The VPN gateway must use cryptographic algorithms approved by NSA to protect NSS when transporting classified traffic across an unclassified network.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VPN gateway must implement cryptographic modules adhering to the higher standards approved by the Federal Government since this provides assurance they have been tested and validated.

NIST cryptographic algorithms approved by NSA to protect NSS. Based on an analysis of the impact of quantum computing, cryptographic algorithms specified by CNSSP-15 and approved for use in products in the CSfC program, the approved algorithms have been changed to more stringent protocols configure with increased bit sizes and other secure characteristics to protect against quantum computing threats. The Commercial National Security Algorithm Suite (CNSA Suite) replaces Suite B.'
  desc 'check', 'Verify the VPN gateway IKE Phase 1 and Phase 2 are configured to use cryptography that is compliant with NSA/CSS parameters when transporting classified traffic across an unclassified network.

If the VPN gateway is not configured to use cryptography that is compliant with NSA/CSS parameters when transporting classified traffic across an unclassified network, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway Internet Key Exchange (IKE) to use cryptography that is compliant with NSA/CSS parameters when transporting classified traffic across an unclassified network.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7522r803443_chk'
  tag severity: 'high'
  tag gid: 'V-207262'
  tag rid: 'SV-207262r878134_rule'
  tag stig_id: 'SRG-NET-000565-VPN-002400'
  tag gtitle: 'SRG-NET-000565'
  tag fix_id: 'F-7522r803444_fix'
  tag 'documentable'
  tag legacy: ['SV-106357', 'V-97219']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
