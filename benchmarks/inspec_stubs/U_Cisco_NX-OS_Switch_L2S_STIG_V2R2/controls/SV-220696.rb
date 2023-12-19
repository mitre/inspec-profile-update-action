control 'SV-220696' do
  title 'The Cisco switch must not have any switchports assigned to the native VLAN.'
  desc 'Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim’s MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker’s VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim’s VLAN ID is used by the switch as the next hop and sent out the trunk port.'
  desc 'check', 'Review the switch configurations and examine all access switch ports. Verify that they do not belong to the native VLAN as shown in the example below:

interface Ethernet0/1
switchport
switchport mode trunk
switchport trunk native vlan 44

interface Ethernet0/2
 switchport
 switchport access vlan 11

interface Ethernet0/3
 switchport
 switchport access vlan 12

If any access switch ports have been assigned to the same VLAN ID as the native VLAN, this is a finding.'
  desc 'fix', 'Configure all access switch ports to a VLAN other than the native VLAN.'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22411r539139_chk'
  tag severity: 'low'
  tag gid: 'V-220696'
  tag rid: 'SV-220696r539671_rule'
  tag stig_id: 'CISC-L2-000270'
  tag gtitle: 'SRG-NET-000512-L2S-000013'
  tag fix_id: 'F-22400r539140_fix'
  tag 'documentable'
  tag legacy: ['SV-110367', 'V-101263']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
