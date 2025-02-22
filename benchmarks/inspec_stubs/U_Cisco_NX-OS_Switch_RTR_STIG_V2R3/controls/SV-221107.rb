control 'SV-221107' do
  title 'The Cisco BGP switch must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Step 1: Verify that a prefix list has been configured containing prefixes belonging to the IP core.

ip prefix-list FILTER_CORE_PREFIXES seq 5 deny x.1.1.0/24 le 32
ip prefix-list FILTER _CORE_PREFIXES seq 10 deny x.1.2.0/24 le 32
ip prefix-list FILTER _CORE_PREFIXES seq 15 permit 0.0.0.0/0 ge 8

Step 2: Verify that the prefix lists has been applied to all external BGP peers as shown in the example below:

router bgp xx
 router-id 10.1.1.1
 neighbor x.1.12.2 remote-as xx
 password 3 7b07d1b3023056a9
 address-family ipv4 unicast
 FILTER _CORE_PREFIXES out
 neighbor x.2.44.4 remote-as xx
 password 3 f07a10cb41db8bb6f8f0a340049a9b02
 address-family ipv4 unicast
 prefix-list FILTER _CORE_PREFIXES out

If the switch is not configured to reject outbound route advertisements for prefixes belonging to the IP core, this is a finding.'
  desc 'fix', 'Step 1: Configure a prefix list for containing all customer and local AS prefixes as shown in the example below:

SW1(config)# ip prefix-list FILTER_CORE_PREFIXES deny x.1.1.0/24 le 32
SW1(config)# ip prefix-list FILTER _CORE_PREFIXES deny x.1.2.0/24 le 32
SW1(config)# ip prefix-list FILTER _CORE_PREFIXES permit 0.0.0.0/0 ge 8

Step 2: Apply the prefix list filter outbound to each CE neighbor as shown in the example below:

SW1(config)# router bgp xx
SW1(config-router)# neighbor x.1.12.2
SW1(config-router-neighbor)# address-family ipv4 unicast
SW1(config-router-neighbor-af)# prefix-list FILTER _CORE_PREFIXES out
SW1(config-router-neighbor-af)# exit
SW1(config-router-neighbor)# exit
SW1(config-router)# neighbor x.2.44.4
SW1(config-router-neighbor)# address-family ipv4 unicast
SW1(config-router-neighbor-af)# prefix-list FILTER _CORE_PREFIXES out 
SW1(config-router-neighbor-af)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22822r409810_chk'
  tag severity: 'medium'
  tag gid: 'V-221107'
  tag rid: 'SV-221107r622190_rule'
  tag stig_id: 'CISC-RT-000530'
  tag gtitle: 'SRG-NET-000205-RTR-000006'
  tag fix_id: 'F-22811r409811_fix'
  tag 'documentable'
  tag legacy: ['SV-111033', 'V-101929']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
