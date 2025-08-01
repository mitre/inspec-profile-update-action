control 'SV-207157' do
  title 'The BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that there is a filter to reject inbound route advertisements that are greater than /24 or the least significant prefixes issued to the customer, whichever is larger.

If the router is not configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer, this is a finding.'
  desc 'fix', 'Ensure all eBGP routers are configured to limit the prefix size on any route advertisement to /24 or the least significant prefixes issued to the customer.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7418r382499_chk'
  tag severity: 'low'
  tag gid: 'V-207157'
  tag rid: 'SV-207157r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000118'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7418r382500_fix'
  tag 'documentable'
  tag legacy: ['SV-92987', 'V-78281']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
