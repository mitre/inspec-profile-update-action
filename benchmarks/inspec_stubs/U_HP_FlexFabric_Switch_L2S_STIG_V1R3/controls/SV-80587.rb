control 'SV-80587' do
  title 'The HP FlexFabric Switch must not have any access switch ports assigned to the native VLAN.'
  desc 'Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim’s MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker’s VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim’s VLAN ID is used by the switch as the next hop and sent out the trunk port.'
  desc 'check', 'Verify all access switch ports are not part of the native VLAN (VLAN 1).

If any access switch port is assigned to the native VLAN (VLAN 1), this is a finding.

<HP>display interface GigabitEthernet brief

Brief information on interface(s) under bridge mode:
Link: ADM - administratively down; Stby - standby
Speed or Duplex: (a)/A - auto; H - half; F - full
Type: A - access; T - trunk; H - hybrid
Interface            Link Speed   Duplex Type PVID Description
GE1/0/1              UP      1G(a)      F(a)        A    1
GE1/0/2              UP      1G(a)      F(a)        A    100
GE1/0/3              UP      10M(a)   F(a)        A    100
XGE1/0/1           UP      10G(a)    F(a)        A    200
XGE1/0/2           UP      10G(a)    F(a)        A    200

If any access switch port are configured for the native vlan.  This is a finding.'
  desc 'fix', 'Remove the native vlan of the trunk ports.

[HP-GigabitEthernet1/0/1] undo port trunk permit vlan 1'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66097'
  tag rid: 'SV-80587r1_rule'
  tag stig_id: 'HFFS-L2-000030'
  tag gtitle: 'SRG-NET-000512-L2S-000013'
  tag fix_id: 'F-72173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
