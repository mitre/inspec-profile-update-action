control 'SV-214530' do
  title 'The Juniper SRX Services Gateway Firewall must implement load balancing on the perimeter firewall, at a minimum, to limit the effects of known and unknown types of Denial of Service (DoS) attacks on the network.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy, which reduces the susceptibility of the ALG to many DoS attacks.

This requirement applies to the network traffic functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.

The Juniper SRX provides a number of methods for load balancing the traffic flow. The device can be configured for filter based forwarding, per flow load balancing, per-packet load balancing, or High Availability (HA) using additional hardware. Since the firewall is considered a critical security system, it is imperative that perimeter firewalls, at a minimum, be safeguarded with redundancy measures such as HA.'
  desc 'check', 'Since load balancing is a highly complex configuration that can be implemented using a wide variety of configurations, ask the site representative to demonstrate the method used and the configuration.

If load balancing is not implemented on the perimeter firewall, this is a finding.'
  desc 'fix', 'Consult vendor configuration guides and knowledge base. Implement one or more methods of load balance (e.g., filter based forwarding, per flow load balancing, per-packet load balancing, or High Availability [HA]).'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15736r297274_chk'
  tag severity: 'medium'
  tag gid: 'V-214530'
  tag rid: 'SV-214530r557389_rule'
  tag stig_id: 'JUSX-AG-000121'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-15734r297275_fix'
  tag 'documentable'
  tag legacy: ['V-66325', 'SV-80815']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
