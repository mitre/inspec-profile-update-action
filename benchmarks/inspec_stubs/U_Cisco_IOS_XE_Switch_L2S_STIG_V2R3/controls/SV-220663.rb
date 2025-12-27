control 'SV-220663' do
  title 'The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.'
  desc 'IGMP and MLD snooping provides a way to constrain multicast traffic at Layer 2. By monitoring the IGMP or MLD membership reports sent by hosts within a VLAN, the snooping application can set up Layer 2 multicast forwarding tables to deliver specific multicast traffic only to interfaces connected to hosts interested in receiving the traffic, thereby significantly reducing the volume of multicast traffic that would otherwise flood the VLAN.'
  desc 'check', 'Review the switch configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively. The example below are the steps to verify that IGMP snooping is enabled for each VLAN.

Step 1: Verify that IGMP or MLD snooping is enabled globally. By default, IGMP snooping is enabled globally; hence, the following command should not be in the switch configuration: 

no ip igmp snooping

Note: For VLANs managed via 802.1x, this check is N/A.

Step 2: Verify that IGMP snooping is not disabled for any VLAN as shown in the example below:

no ip igmp snooping vlan 11

Note: When globally enabled, it is also enabled by default on all VLANs, but can be disabled on a per-VLAN basis. If global snooping is disabled, VLAN snooping cannot be enabled. 

If the switch is not configured to implement IGMP or MLD snooping for each VLAN, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively globally.

SW1(config)#ip igmp snooping'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22378r802437_chk'
  tag severity: 'low'
  tag gid: 'V-220663'
  tag rid: 'SV-220663r802438_rule'
  tag stig_id: 'CISC-L2-000170'
  tag gtitle: 'SRG-NET-000512-L2S-000002'
  tag fix_id: 'F-22367r507538_fix'
  tag 'documentable'
  tag legacy: ['SV-110297', 'V-101193']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
