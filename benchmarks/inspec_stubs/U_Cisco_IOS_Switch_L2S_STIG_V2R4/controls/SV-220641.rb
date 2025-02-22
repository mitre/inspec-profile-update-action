control 'SV-220641' do
  title 'The Cisco switch must have all disabled switch ports assigned to an unused VLAN.'
  desc 'A disabled port that is assigned to a user or management VLAN may become enabled by accident or by an attacker and as a result may gain access to that VLAN as a member.'
  desc 'check', 'Step 1: Review the switch configurations and examine all access switch ports. Each access switch port not in use should have membership to an inactive VLAN. 

interface GigabitEthernet0/0
 switchport access vlan 999
 shutdown
!
interface GigabitEthernet0/1
 switchport access vlan 999
 shutdown
…
…
…
interface GigabitEthernet0/9
 switchport access vlan 999
 shutdown

Step 2: Verify that traffic from the inactive VLAN is not allowed on any trunk links as shown in the example below:

interface GigabitEthernet1/1
 switchport trunk allowed vlan 1-998,1000-4094
 switchport trunk encapsulation dot1q
 switchport mode trunk

Note: Switch ports configured for 802.1x are exempt from this requirement.

If any access switch ports are not in use and not in an inactive VLAN, this is a finding.'
  desc 'fix', 'Assign all switch ports not in use to an inactive VLAN.

Step 1: Assign the disabled interfaces to an inactive VLAN:

SW3(config)#int range g0/0 – 9
SW3(config-if-range)# switchport access vlan 999

Step 2: Configure trunk links to not allow traffic from the inactive VLAN:

SW3(config)#int g1/1
SW3(config-if)#switchport trunk allowed vlan except 999'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22356r507969_chk'
  tag severity: 'medium'
  tag gid: 'V-220641'
  tag rid: 'SV-220641r539671_rule'
  tag stig_id: 'CISC-L2-000210'
  tag gtitle: 'SRG-NET-000512-L2S-000007'
  tag fix_id: 'F-22345r507970_fix'
  tag 'documentable'
  tag legacy: ['SV-110253', 'V-101149']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
