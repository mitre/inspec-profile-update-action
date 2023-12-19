control 'SV-216597' do
  title 'The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.'
  desc 'Accepting route advertisements for Bogon prefixes can result in the local autonomous system (AS) becoming a transit for malicious traffic as it will in turn advertise these prefixes to neighbor autonomous systems.'
  desc 'check', 'Review the router configuration to verify that it will reject BGP routes for any Bogon prefixes.

Step 1: Verify a prefix list has been configured containing the current Bogon prefixes as shown in the example below.

ip prefix-list PREFIX_FILTER seq 5 deny 0.0.0.0/8 le 32
ip prefix-list PREFIX_FILTER seq 10 deny 10.0.0.0/8 le 32
ip prefix-list PREFIX_FILTER seq 15 deny 100.64.0.0/10 le 32
ip prefix-list PREFIX_FILTER seq 20 deny 127.0.0.0/8 le 32
ip prefix-list PREFIX_FILTER seq 25 deny 169.254.0.0/16 le 32
ip prefix-list PREFIX_FILTER seq 30 deny 172.16.0.0/12 le 32
ip prefix-list PREFIX_FILTER seq 35 deny 192.0.2.0/24 le 32
ip prefix-list PREFIX_FILTER seq 40 deny 192.88.99.0/24 le 32
ip prefix-list PREFIX_FILTER seq 45 deny 192.168.0.0/16 le 32
ip prefix-list PREFIX_FILTER seq 50 deny 198.18.0.0/15 le 32
ip prefix-list PREFIX_FILTER seq 55 deny 198.51.100.0/24 le 32
ip prefix-list PREFIX_FILTER seq 60 deny 203.0.113.0/24 le 32
ip prefix-list PREFIX_FILTER seq 65 deny 224.0.0.0/4 le 32
ip prefix-list PREFIX_FILTER seq 70 deny 240.0.0.0/4 le 32
ip prefix-list PREFIX_FILTER seq 75 permit 0.0.0.0/0 ge 8

Step 2: Verify that the prefix list has been applied to all external BGP peers as shown in the example below.

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 prefix-list PREFIX_FILTER in
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 prefix-list PREFIX_FILTER in

Route Map Alternative 

Verify that the route map applied to the external neighbors references the configured Bogon prefix list shown above.

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 route-map FILTER_PREFIX_MAP
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 route-map FILTER_PREFIX_MAP
…
route-map FILTER_PREFIX_MAP permit 10
 match ip address prefix-list PREFIX_FILTER

If the router is not configured to reject inbound route advertisements for any Bogon prefixes, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements for any Bogon prefixes.

Step 1: Configure a prefix list containing the current Bogon prefixes as shown below.

R1(config)#ip prefix-list PREFIX_FILTER deny 0.0.0.0/8 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 10.0.0.0/8 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 100.64.0.0/10 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 127.0.0.0/8 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 169.254.0.0/16 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 172.16.0.0/12 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 192.0.2.0/24 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 192.88.99.0/24 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 192.168.0.0/16 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 198.18.0.0/15 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 198.51.100.0/24 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 203.0.113.0/24 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 224.0.0.0/4 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 240.0.0.0/4 le 32
R1(config)#ip prefix-list PREFIX_FILTER deny 240.0.0.0/4 le 32
R1(config)#ip prefix-list PREFIX_FILTER permit 0.0.0.0/0 ge 8

Step 2: Apply the prefix list filter inbound to each external BGP neighbor as shown in the example.

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.1.9 prefix-list PREFIX_FILTER in
R1(config-router)#neighbor x.2.1.7 prefix-list PREFIX_FILTER in

Route Map Alternative 

Step 1: Configure the route map referencing the configured prefix list above.

R1(config)#route-map FILTER_PREFIX_MAP 10
R1(config-route-map)#match ip address prefix-list PREFIX_FILTER
R1(config-route-map)#exit

Step 2: Apply the route-map inbound to each external BGP neighbor as shown in the example.

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.1.9 route-map FILTER_PREFIX_MAP in
R1(config-router)#neighbor x.2.1.7 route-map FILTER_PREFIX_MAP in 
R1(config-router)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17832r287163_chk'
  tag severity: 'medium'
  tag gid: 'V-216597'
  tag rid: 'SV-216597r531085_rule'
  tag stig_id: 'CISC-RT-000490'
  tag gtitle: 'SRG-NET-000018-RTR-000002'
  tag fix_id: 'F-17828r287164_fix'
  tag 'documentable'
  tag legacy: ['SV-105733', 'V-96595']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
