control 'SV-255984' do
  title 'The Arista MLS layer 2 switch must have all user-facing or untrusted ports configured as access switch ports.'
  desc "Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim's MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker's VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim's VLAN ID is used by the switch as the next hop and sent out the trunk port."
  desc 'check', 'Review the Arista MLS switch configurations and examine all user-facing or untrusted switch ports configured as access switch ports.

switch(config)# show run interface ethernet 13 - 15 
interface Ethernet13
   switchport access vlan 100
interface Ethernet14
   switchport access vlan 100
interface Ethernet14
   switchport access vlan 100

If any of the user-facing switch ports are configured as a trunk, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to disable trunking on all user-facing or untrusted switch ports.

switch{config)#interface ethernet 13 - 15
switch(config-if-Et13-15)#description disable trunking untrusted ports
switch(config-if-Et13-15)#switchport mode access
switch(config-if-Et13-15)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59660r882292_chk'
  tag severity: 'medium'
  tag gid: 'V-255984'
  tag rid: 'SV-255984r882294_rule'
  tag stig_id: 'ARST-L2-000210'
  tag gtitle: 'SRG-NET-000512-L2S-000011'
  tag fix_id: 'F-59603r882293_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
