control 'SV-255986' do
  title 'The Arista MLS layer 2 switch must not have any switch ports assigned to the native VLAN.'
  desc 'Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim’s MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker’s VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim’s VLAN ID is used by the switch as the next hop and sent out the trunk port.'
  desc 'check', 'Review the configuration for all trunking ports to determine the native VLAN by using the following example (for vlan 1000):

switch(config-if-Et4)#sh run int eth4
interface Ethernet4
   description STIG Disable_VLAN 1 and native vlan to 1000
   switchport trunk native vlan 1000
   switchport trunk allowed vlan 2-999,1001-4094
switch(config-if-Et4)#

Review the configuration to ensure no access switch ports are configured in the native VLAN by using the following example (for vlan 1000):

swtich#sh vlan brief
VLAN  Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
1     default                              
8     VLAN0008                         active    Cpu
25    VLAN0025                        active    Cpu
100   VLAN0100                       active    Cpu
1000  VLAN1000                      active   
4090  VLAN4090                      active    

If any access switch ports have been assigned to the same VLAN ID as the native VLAN, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch to ensure all access switch ports use a VLAN other than the native VLAN.

Configure all access switch ports to a VLAN other than the designated native VLAN by using the following example:

switch(config)#interface Ethernet 21
switch(config-Eth21)# switchport access vlan xxxx'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59662r882298_chk'
  tag severity: 'low'
  tag gid: 'V-255986'
  tag rid: 'SV-255986r882300_rule'
  tag stig_id: 'ARST-L2-000230'
  tag gtitle: 'SRG-NET-000512-L2S-000013'
  tag fix_id: 'F-59605r882299_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
