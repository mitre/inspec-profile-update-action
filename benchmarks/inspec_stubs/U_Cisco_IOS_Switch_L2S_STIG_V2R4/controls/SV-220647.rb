control 'SV-220647' do
  title 'The Cisco switch must not have any switchports assigned to the native VLAN.'
  desc 'Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim’s MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. 

The outer tag that will have the attacker’s VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim’s VLAN ID is used by the switch as the next hop and sent out the trunk port.'
  desc 'check', 'Review the switch configurations and examine all access switch ports. Verify that they do not belong to the native VLAN as shown in the example below:

interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
 switchport trunk native vlan 44
 switchport mode trunk
 negotiation auto
!
interface GigabitEthernet0/2
 switchport access vlan 11
 negotiation auto
!
interface GigabitEthernet0/3
 switchport access vlan 12
 negotiation auto
!

If any access switch ports have been assigned to the same VLAN ID as the native VLAN, this is a finding.'
  desc 'fix', 'Configure all access switch ports to a VLAN other than the native VLAN.'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22362r507987_chk'
  tag severity: 'low'
  tag gid: 'V-220647'
  tag rid: 'SV-220647r539671_rule'
  tag stig_id: 'CISC-L2-000270'
  tag gtitle: 'SRG-NET-000512-L2S-000013'
  tag fix_id: 'F-22351r507988_fix'
  tag 'documentable'
  tag legacy: ['SV-110265', 'V-101161']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
