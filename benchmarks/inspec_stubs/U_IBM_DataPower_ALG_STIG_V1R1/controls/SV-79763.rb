control 'SV-79763' do
  title 'The DataPower Gateway must implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy; which service redundancy reduces the susceptibility of the ALG to many DoS attacks.

The ALG must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing.

This requirement applies to the network traffic functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.'
  desc 'check', 'Type “Load Balancer Group” in nav search.

Check the configuration of all active services and verify that the XML Manager used by the service has an active Load Balancer Group.

If no Load Balancer group is present, this is a finding.'
  desc 'fix', 'Type “Load Balancer Group” in nav search >> Add >> Algorithm select algorithm. 

Type “XML Manager” in nav search >> Add >> Load Balance Groups load balance group. 

Associate this XML Manager with all active services.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65901r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65273'
  tag rid: 'SV-79763r1_rule'
  tag stig_id: 'WSDP-AG-000100'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-71213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
