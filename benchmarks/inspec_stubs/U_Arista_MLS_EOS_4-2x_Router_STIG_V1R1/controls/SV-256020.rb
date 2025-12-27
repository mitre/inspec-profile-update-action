control 'SV-256020' do
  title 'The Arista BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Review the Arista router configuration to verify a filter is defined to block route advertisements for prefixes that belong to the IP core.

The prefix filter must be referenced outbound on the appropriate BGP neighbor statements.

Step 1: The following example creates an outbound route advertise filter and configures CE Arista MLS to advertise the filter to IP Core PE (100.1.0.128). An IP prefix list named FILTER_OUT is created to specify the 172.16.1.0/24 subnet for outbound route advertisements filtering.

ip prefix-list FILTER_OUT seq 10 permit 172.16.1.0/24 

Step 2: Verify the outbound prefix list is applied to the appropriate BGP neighbor in the BGP process. Execute the command "sh run section router bgp".

router bgp 65001
 neighbor 100.1.0.128 remote-as 65200
 neighbor 100.1.0.128 prefix-list FILTER_OUT out
 exit

If the Arista router is not configured to reject outbound route advertisements that belong to the IP core, this is a finding.'
  desc 'fix', 'Configure all eBGP Arista routers to filter outbound route advertisements belonging to the IP core.

Step 1: Configure an outbound route advertise filter and configure CE Arista MLS to advertise the filter to IP Core PE (100.1.0.128). Also configure an IP prefix list named FILTER_OUT to specify the 172.16.1.0/24 subnet for outbound route advertisements filtering.

LEAF-1A(config)#ip prefix-list FILTER_OUT seq 10 permit 172.16.1.0/24 

Step 2: Apply the prefix-list outbound with the BGP neighbor in BGP process.

LEAF-1A(config)#router bgp 65001
LEAF-1A(config-router-bgp)#neighbor 100.1.0.128 remote-as 65200
LEAF-1A(config-router-bgp)#neighbor 100.1.0.128 prefix-list FILTER_OUT out
LEAF-1A(config-router-bgp)# exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59696r882400_chk'
  tag severity: 'medium'
  tag gid: 'V-256020'
  tag rid: 'SV-256020r882402_rule'
  tag stig_id: 'ARST-RT-000390'
  tag gtitle: 'SRG-NET-000205-RTR-000006'
  tag fix_id: 'F-59639r882401_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
