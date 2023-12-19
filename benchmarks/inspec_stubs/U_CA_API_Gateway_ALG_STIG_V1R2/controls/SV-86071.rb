control 'SV-86071' do
  title 'The CA API Gateway must only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application-level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.

CA API Gateway must use services, policy, and iptable configurations to enforce flows only to/from authorized sources and destinations.'
  desc 'check', 'Open the CA API Gateway - Policy Manager, select "Tasks" from the main menu, and chose "Manage Listen Ports". 

Click the "Manage Firewall Rules" button and verify the proper Firewall Rules have been configured in accordance with organizational requirements for routing communications between authorized sources and destinations. 

Additionally, double-click each of the Registered Services and verify their policies have the proper logic to route the communications traffic to and from authorized sources and destinations.

If either the firewall rules or the policy logic is not configured properly, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager, select "Tasks" from the main menu, and chose "Manage Listen Ports". 

Click the "Manage Firewall Rules" button and add the proper Firewall Rules in accordance with organizational requirements for routing communications between authorized sources and destinations. 

Additionally, double-click each of the Registered Services and add the proper logic to route the communications traffic to and from authorized sources and destinations within their policies in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71447'
  tag rid: 'SV-86071r1_rule'
  tag stig_id: 'CAGW-GW-000700'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-77765r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
