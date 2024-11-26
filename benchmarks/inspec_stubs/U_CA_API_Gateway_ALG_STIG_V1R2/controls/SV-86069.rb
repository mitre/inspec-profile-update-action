control 'SV-86069' do
  title 'The CA API Gateway must implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy, which reduces the susceptibility of the ALG to many DoS attacks.

The ALG must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing.

This requirement applies to the network traffic functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.

The CA API Gateway is designed to run as a cluster behind any industry standard load balancer. When routing to back-end services, the Gateway itself can also provide load balancing across back ends as described in the Check and Fix content if needed to support additional protection against DoS attacks.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring load balancing. 

Verify there is a "Route via HTTP(S)" Assertion included in the policy and double-click it. 

Click the "Connection" button and verify either the "Use the following IP addresses:" or "Use multiple URLs:" radio button is selected and that multiple URLs/IP addresses are listed in the box. 

If the assertion is not included within the policies or multiple URLs/IP addresses are not being used, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring load balancing. 

Verify/add a "Route via HTTP(s)" Assertion within the policy and double-click it. 

Click the "Connection" button and chose either the "Use the following IP addresses:" or "Use multiple URLs:" radio button. 

Configure multiple IP addresses/URLs and set the Failover strategy in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71445'
  tag rid: 'SV-86069r1_rule'
  tag stig_id: 'CAGW-GW-000680'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-77763r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
