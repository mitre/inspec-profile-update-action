control 'SV-256036' do
  title 'The Arista BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration to verify there is a filter to reject inbound route advertisements that are greater than /24 or the least significant prefixes issued to the customer, whichever is larger.

Step 1: To verify there is a filter to reject inbound route advertisements that are greater than /24 or the least significant prefixes issued to the customer, whichever is larger, execute the command "sh ip prefix-list".

ip prefix-list ADVERTISE_ROUTES deny 0.0.0.0/0 ge 25
ip prefix-list ADVERTISE_ROUTES permit 0.0.0.0/0 le 32

Step 2: Verify the prefix-list is applied in BGP process. Execute the command "sh run section router bgp".

router bgp 65000
 neighbor 10.1.12.2 prefix-list ADVERTISE_ROUTES in

If the Arista router is not configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone. 

Ensure all eBGP Arista routers are configured to limit the prefix size on any route advertisement to /24 or the least significant prefixes issued to the customer.

Step 1: Configure the prefix-list.

ip prefix-list ADVERTISE_ROUTES deny 0.0.0.0/0 ge 25
ip prefix-list ADVERTISE_ROUTES permit 0.0.0.0/0 le 32

Step 2: Apply the prefix-list in the BGP process inbound.

LEAF-1A(config)#router bgp 65000
LEAF-1A(config)# neighbor 10.1.12.2 prefix-list ADVERTISE_ROUTES in'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59712r882448_chk'
  tag severity: 'low'
  tag gid: 'V-256036'
  tag rid: 'SV-256036r882450_rule'
  tag stig_id: 'ARST-RT-000570'
  tag gtitle: 'SRG-NET-000362-RTR-000118'
  tag fix_id: 'F-59655r882449_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
