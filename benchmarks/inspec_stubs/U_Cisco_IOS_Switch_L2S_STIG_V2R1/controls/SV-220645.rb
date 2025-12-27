control 'SV-220645' do
  title 'The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.'
  desc "Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim's MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. 

The outer tag that will have the attacker's VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim's VLAN ID is used by the switch as the next hop and sent out the trunk port."
  desc 'check', 'Review the switch configurations and examine all user-facing or untrusted switchports. The example below depicts both access and trunk ports:

interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
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

If any of the user-facing switch ports are configured as a trunk, this is a finding.'
  desc 'fix', 'Disable trunking on all user-facing or untrusted switch ports:

SW1(config)#int g0/6
SW1(config-if)#switchport mode access
SW1(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22360r507981_chk'
  tag severity: 'medium'
  tag gid: 'V-220645'
  tag rid: 'SV-220645r539671_rule'
  tag stig_id: 'CISC-L2-000250'
  tag gtitle: 'SRG-NET-000512-L2S-000011'
  tag fix_id: 'F-22349r507982_fix'
  tag 'documentable'
  tag legacy: ['V-101157', 'SV-110261']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
