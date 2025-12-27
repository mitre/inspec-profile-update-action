control 'SV-206662' do
  title 'The layer 2 switch must have IGMP or MLD Snooping configured on all VLANs'
  desc 'IGMP and MLD snooping provides a way to constrain multicast traffic at Layer 2. By monitoring the IGMP or MLD membership reports sent by hosts within a VLAN, the snooping application can set up Layer 2 multicast forwarding tables to deliver specific multicast traffic only to interfaces connected to hosts interested in receiving the traffic, thereby significantly reducing the volume of multicast traffic that would otherwise flood the VLAN.'
  desc 'check', 'Review the switch configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively.

If the switch is not configured to implement IGMP or MLD snooping for each VLAN, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VLAN.'
  impact 0.3
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6920r298416_chk'
  tag severity: 'low'
  tag gid: 'V-206662'
  tag rid: 'SV-206662r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000002'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6920r298417_fix'
  tag 'documentable'
  tag legacy: ['SV-105019', 'V-95881']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
