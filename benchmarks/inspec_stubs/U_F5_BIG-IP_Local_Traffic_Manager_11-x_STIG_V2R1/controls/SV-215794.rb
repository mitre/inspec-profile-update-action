control 'SV-215794' do
  title 'The BIG-IP Core implementation must be configured to only allow incoming communications from authorized sources routed to authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application-level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.'
  desc 'check', 'If the BIG-IP Core does not perform packet-filtering intermediary services for virtual servers, this is not applicable.

When packet-filtering intermediary services are performed, verify the BIG-IP Core is configured to only allow incoming communications from authorized sources routed to authorized destinations as follows:

Verify Virtual Server(s) are configured in the BIG-IP LTM module with policies to only allow incoming communications from authorized sources routed to authorized destinations.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Network Firewall" Enforcement is set to "Policy Rules..." and "Policy" is set to use an AFM policy to only allow incoming communications from authorized sources routed to authorized destinations.

If the BIG-IP Core is configured to allow incoming communications from unauthorized sources routed to unauthorized destinations, this is a finding.'
  desc 'fix', 'If user packet-filtering intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP AFM module to only allow incoming communications from authorized sources routed to authorized destinations.

Apply the AFM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to only allow incoming communications from authorized sources routed to authorized destinations.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16986r291195_chk'
  tag severity: 'medium'
  tag gid: 'V-215794'
  tag rid: 'SV-215794r557356_rule'
  tag stig_id: 'F5BI-LT-000223'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-16984r291196_fix'
  tag 'documentable'
  tag legacy: ['V-60369', 'SV-74799']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
