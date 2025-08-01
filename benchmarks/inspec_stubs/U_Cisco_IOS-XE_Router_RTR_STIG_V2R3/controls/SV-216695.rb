control 'SV-216695' do
  title 'The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if it is compliant with this requirement.

Step 1: Verify that a route filter has been configured to reject prefixes longer than /24, or the least significant prefixes issued to the customers as shown in the example below:

ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24
ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32

Step 2: Verify that prefix filtering has been applied to each eBGP peer as shown in the example:

router bgp xx
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 prefix-list FILTER_PREFIX_LENGTH in
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 prefix-list FILTER_PREFIX_LENGTH in


If the router is not configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to limit the prefix size on any route advertisement to /24 or the least significant prefixes issued to the customer.

Step 1: Configure a prefix list to reject any prefix that is longer than /24.

R1(config)#ip prefix-list FILTER_PREFIX_LENGTH permit 0.0.0.0/0 ge 8 le 24
R1(config)#ip prefix-list FILTER_PREFIX_LENGTH deny  0.0.0.0/0 le 32


Step 2: Apply the prefix list to all eBGP peers as shown in the example below.

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.1.9 prefix-list FILTER_PREFIX_LENGTH in
R1(config-router)#neighbor x.2.1.7 prefix-list FILTER_PREFIX_LENGTH in'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17928r288030_chk'
  tag severity: 'low'
  tag gid: 'V-216695'
  tag rid: 'SV-216695r531086_rule'
  tag stig_id: 'CISC-RT-000570'
  tag gtitle: 'SRG-NET-000362-RTR-000118'
  tag fix_id: 'F-17926r288031_fix'
  tag 'documentable'
  tag legacy: ['SV-106101', 'V-96963']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
