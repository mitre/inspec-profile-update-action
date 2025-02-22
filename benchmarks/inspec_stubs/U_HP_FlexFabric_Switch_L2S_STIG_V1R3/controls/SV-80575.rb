control 'SV-80575' do
  title 'The HP FlexFabric Switch must have all disabled switch ports assigned an unused VLAN.'
  desc 'It is possible that a disabled port that is assigned to a user or management VLAN becomes enabled by accident or by an attacker and as a result gains access to that VLAN as a member.'
  desc 'check', 'Review the HP FlexFabric Switch configurations and examine all access switch ports.  Each access switch port not in use should have membership to an inactive VLAN that is not used for any purpose and is not allowed on any trunk links.

If there are any access switch ports not in use and not in an inactive VLAN, this is a finding.

<HP>display vlan X
 VLAN ID: X
 VLAN type: Static
 Route interface: Configured:
 Description: VLAN 000X
 Name: VLAN 000X
 Tagged ports:   None
 Untagged ports:
    GigabitEthernet1/0/1          GigabitEthernet1/0/2
    GigabitEthernet1/0/3          GigabitEthernet1/0/4'
  desc 'fix', 'Assign all switch ports not in use to an inactive VLAN.

[HP-vlanX]port GigabitEthernet 1/0/1 to GigabitEthernet 1/0/48'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66085'
  tag rid: 'SV-80575r1_rule'
  tag stig_id: 'HFFS-L2-000024'
  tag gtitle: 'SRG-NET-000512-L2S-000007'
  tag fix_id: 'F-72161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
