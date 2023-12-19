control 'SV-221031' do
  title 'The Cisco BGP switch must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix de-aggregation can degrade switch performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured switch, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', 'Review the switch configuration to determine if it is compliant with this requirement.

Step 1: Verify that a route filter has been configured to reject prefixes longer than /24, or the least significant prefixes issued to the customers as shown in the example below:

ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24
ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32

Step 2: Verify that prefix filtering has been applied to each eBGP peer as shown in the example:

router bgp xx
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 prefix-list FILTER_PREFIX_LENGTH in
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 prefix-list FILTER_PREFIX_LENGTH in

If the switch is not configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer, this is a finding.'
  desc 'fix', 'Configure the switch to limit the prefix size on any route advertisement to /24, or the least significant prefixes issued to the customer.

Step 1: Configure a prefix list to reject any prefix that is longer than /24.

SW1(config)#ip prefix-list FILTER_PREFIX_LENGTH permit 0.0.0.0/0 ge 8 le 24
SW1(config)#ip prefix-list FILTER_PREFIX_LENGTH deny 0.0.0.0/0 le 32

Step 2: Apply the prefix list to all eBGP peers as shown in the example below:

SW1(config)#router bgp xx
SW1(config-switch)#neighbor x.1.1.9 prefix-list FILTER_PREFIX_LENGTH in
SW1(config-switch)#neighbor x.2.1.7 prefix-list FILTER_PREFIX_LENGTH in'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22746r408887_chk'
  tag severity: 'low'
  tag gid: 'V-221031'
  tag rid: 'SV-221031r856417_rule'
  tag stig_id: 'CISC-RT-000570'
  tag gtitle: 'SRG-NET-000362-RTR-000118'
  tag fix_id: 'F-22735r408888_fix'
  tag 'documentable'
  tag legacy: ['SV-110883', 'V-101779']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
