control 'SV-220690' do
  title 'The Cisco switch must have all disabled switch ports assigned to an unused VLAN.'
  desc 'It is possible that a disabled port that is assigned to a user or management VLAN becomes enabled by accident or by an attacker and as a result gains access to that VLAN as a member.'
  desc 'check', 'Step 1: Review the switch configurations and examine all access switch ports. Each access switch port not in use should have membership to an inactive VLAN. 

interface Ethernet1/81
 shutdown
 switchport access vlan 999

interface Ethernet1/82
 shutdown
 switchport access vlan 999

interface Ethernet1/83
 shutdown
 switchport access vlan 999

Step 2: Verify that traffic from the inactive VLAN is not allowed on any trunk links as shown in the example below:

interface Ethernet1/1
 switchport mode trunk
 switchport trunk allowed vlan 1-998,1000-4094

Note: Switch ports configured for 802.1x are exempt from this requirement.

If there are any access switch ports not in use and not in an inactive VLAN, this is a finding.'
  desc 'fix', 'Assign all switch ports not in use to an inactive VLAN.

Step 1: Assign the disabled interfaces to an inactive VLAN.

SW1(config)# int e1/81-128
SW1(config-if-range)# switchport access vlan 999
SW1(config-if-range)# end

Step 2: Configure trunk links to not allow traffic from the inactive VLAN.

SW1(config-if)# switchport trunk allowed vlan except 999
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22405r539121_chk'
  tag severity: 'medium'
  tag gid: 'V-220690'
  tag rid: 'SV-220690r539671_rule'
  tag stig_id: 'CISC-L2-000210'
  tag gtitle: 'SRG-NET-000512-L2S-000007'
  tag fix_id: 'F-22394r539122_fix'
  tag 'documentable'
  tag legacy: ['SV-110355', 'V-101251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
