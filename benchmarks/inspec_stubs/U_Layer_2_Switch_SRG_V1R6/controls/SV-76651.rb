control 'SV-76651' do
  title 'The layer 2 switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.'
  desc "VLAN Trunk Protocol (VTP) provides central management of VLAN domains, thus reducing administration in a switched network. When configuring a new VLAN on a VTP server, the VLAN is distributed through all switches in the domain. This reduces the need to configure the same VLAN everywhere. VTP pruning preserves bandwidth by preventing VLAN traffic (unknown MAC, broadcast, multicast) from being sent down trunk links when not needed, that is, there are no access switch ports in neighboring switches belonging to such VLANs. An attack can force a digest change for the VTP domain enabling a rogue device to become the VTP server, which could allow unauthorized access to previously blocked VLANs or allow the addition of unauthorized switches into the domain. Authenticating VTP messages with a cryptographic hash function can reduce the risk of the VTP domain's being compromised."
  desc 'check', 'Review the switch configuration to verify if VTP is enabled. If VTP is enabled, verify that authentication has been configured.

If VTP has been configured on the switch and is not authenticating VTP messages with a hash function using the most secured cryptographic algorithm available, this is a finding.'
  desc 'fix', 'Configure the switch to authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62965r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62161'
  tag rid: 'SV-76651r1_rule'
  tag stig_id: 'SRG-NET-000168-L2S-000019'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-68081r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
