control 'SV-221024' do
  title 'The Cisco BGP switch must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping or being black-holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Review the switch configuration to verify that it will reject routes belonging to the local AS.

Step 1: Verify a prefix list has been configured containing prefixes belonging to the local AS. In the example below x.13.1.0/24 is the global address space allocated to the local AS.

ip prefix-list PREFIX_FILTER seq 5 deny 0.0.0.0/8 le 32
…
…
…
ip prefix-list PREFIX_FILTER seq 74 deny x.13.1.0/24 le 32
ip prefix-list PREFIX_FILTER seq 75 permit 0.0.0.0/0 ge 8

Step 2: Verify that the prefix list has been applied to all external BGP peers as shown in the example below:

 router bgp xx
no synchronization
bgp log-neighbor-changes
neighbor x.1.1.9 remote-as yy
neighbor x.1.1.9 prefix-list PREFIX_FILTER in
neighbor x.2.1.7 remote-as zz
neighbor x.2.1.7 prefix-list PREFIX_FILTER in

If the switch is not configured to reject inbound route advertisements belonging to the local AS, this is a finding.'
  desc 'fix', 'Review the switch configuration to verify that it will reject routes belonging to the local AS.

Configure the router to reject inbound route advertisements for any prefixes belonging to the local AS.

Step 1: Add to the prefix filter list those prefixes belonging to the local autonomous system.

SW1(config)#ip prefix-list PREFIX_FILTER seq 74 deny x.13.1.0/24 le 32

Step 2: If not already completed to be compliant with previous requirement, apply the prefix list filter inbound to each external BGP neighbor as shown in the example.

SW1(config)#switch bgp xx
SW1(config-switch)#neighbor x.1.1.9 prefix-list PREFIX_FILTER in
SW1(config-switch)#neighbor x.2.1.7 prefix-list PREFIX_FILTER in
SW1(config-switch)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22739r408866_chk'
  tag severity: 'medium'
  tag gid: 'V-221024'
  tag rid: 'SV-221024r622190_rule'
  tag stig_id: 'CISC-RT-000500'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag fix_id: 'F-22728r408867_fix'
  tag 'documentable'
  tag legacy: ['SV-110869', 'V-101765']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
