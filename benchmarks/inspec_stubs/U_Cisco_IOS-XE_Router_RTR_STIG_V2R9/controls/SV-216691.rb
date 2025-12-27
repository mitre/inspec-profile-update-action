control 'SV-216691' do
  title 'The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Step 1: Verify that a prefix list has been configured containing prefixes belonging to the IP core.

ip prefix-list FILTER_CORE_PREFIXES seq 5 deny x.1.1.0/24 le 32
ip prefix-list FILTER _CORE_PREFIXES seq 10 deny x.1.2.0/24 le 32
ip prefix-list FILTER _CORE_PREFIXES seq 15 permit 0.0.0.0/0 ge 8

Step 2: Verify that the prefix lists has been applied to all external BGP peers as shown in the example below:

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.4.12 remote-as yy
 address-family ipv4 
  neighbor x.1.4.12 prefix-list FILTER _CORE_PREFIXES out

If the router is not configured to reject outbound route advertisements for prefixes belonging to the IP core, this is a finding.'
  desc 'fix', 'Step 1: Configure a prefix list for containing all customer and local AS prefixes as shown in the example below:

R1(config)#ip prefix-list FILTER_CORE_PREFIXES deny x.1.1.0/24 le 32
R1(config)#ip prefix-list FILTER _CORE_PREFIXES deny x.1.2.0/24 le 32
R1(config)#ip prefix-list FILTER _CORE_PREFIXES permit 0.0.0.0/0 ge 8

Step 2: Apply the prefix list filter outbound to each CE neighbor as shown in the example.

router bgp xx
 address-family ipv4
  neighbor x.1.4.12 prefix-list FILTER _CORE_PREFIXES out'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17924r929056_chk'
  tag severity: 'medium'
  tag gid: 'V-216691'
  tag rid: 'SV-216691r929058_rule'
  tag stig_id: 'CISC-RT-000530'
  tag gtitle: 'SRG-NET-000205-RTR-000006'
  tag fix_id: 'F-17922r929057_fix'
  tag 'documentable'
  tag legacy: ['SV-106093', 'V-96955']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
