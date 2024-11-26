control 'SV-110363' do
  title 'The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.'
  desc "Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim's MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker's VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim's VLAN ID is used by the switch as the next hop and sent out the trunk port."
  desc 'check', 'Review the switch configurations and examine all user-facing or untrusted switchports. The example below depicts both access and trunk ports.

interface Ethernet1/1
 switchport
 switchport mode trunk
 switchport trunk allowed vlan 1-998,1000-4094

interface Ethernet1/2
 switchport
 switchport mode trunk
 switchport trunk allowed vlan 2-998,1000-4094

interface Ethernet1/3

interface Ethernet1/4
 switchport access vlan 10

Note: switchport mode access is the default and hence will not be shown in the configuration.

If any of the user-facing switch ports are configured as a trunk, this is a finding.'
  desc 'fix', 'Disable trunking on all user-facing or untrusted switch ports.

SW1(config)# int e1/3-128
SW1(config-if)# switchport mode access
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101259'
  tag rid: 'SV-110363r1_rule'
  tag stig_id: 'CISC-L2-000250'
  tag gtitle: 'SRG-NET-000512-L2S-000011'
  tag fix_id: 'F-106963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
