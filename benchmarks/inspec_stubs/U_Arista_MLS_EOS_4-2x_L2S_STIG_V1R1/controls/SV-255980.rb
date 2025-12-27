control 'SV-255980' do
  title 'The Arista MLS layer 2 switch must have all disabled switch ports assigned to an unused VLAN.'
  desc 'It is possible that a disabled port that is assigned to a user or management VLAN becomes enabled by accident or by an attacker and as a result gains access to that VLAN as a member.'
  desc 'check', 'Step 1: Review the switch configuration and examine all access switch ports. Verify the unused port is configured to be intentionally shut down and assigned to an inactive VLAN.

switch(config)#sh run int eth8
interface Ethernet8
   description PORT IS INTENTIONALLY SHUTDOWN
   switchport access vlan 999
   shutdown
switch(config)# 

Step 2: Verify traffic from the inactive VLAN is not allowed on any trunk links as shown in the example below:

switch(config)#sh run int eth9
interface Ethernet9
   switchport trunk native vlan 1000
   switchport trunk allowed vlan 2-998, 1001-4094
   switchport mode trunk
switch(config)# 

If any access switch ports are not in use and not in an inactive shutdown, this is a finding.

Note: Switch ports configured for 802.1x are exempt from this requirement.'
  desc 'fix', 'Configure all Arista MLS switch ports not in use to be shut down and assigned to an unused VLAN.

Step 1: Configure all unused ports to be shut down and assigned to an unused VLAN.

switch(config)#interface ethernet 9
switch(config-eth9)#shutdown
switch(config-eth9)# description this port is intentionally shutdown
switch(config-eth9)# switchport access vlan 999

Step 2: Configure any trunk links to exclude the unused VLAN.

switch(config)# interface ethernet 10
switch(config-eth10)# switchport trunk native vlan 1000
switch(config-eth9)# switchport trunk allowed vlan 2-998, 1001-4094
switch(config-eth9)# switchport mode trunk'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59656r882280_chk'
  tag severity: 'medium'
  tag gid: 'V-255980'
  tag rid: 'SV-255980r882282_rule'
  tag stig_id: 'ARST-L2-000170'
  tag gtitle: 'SRG-NET-000512-L2S-000007'
  tag fix_id: 'F-59599r882281_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
