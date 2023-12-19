control 'SV-95507' do
  title 'SDN controller must be configured to forward traffic based on security requirements.'
  desc 'For security reasons, an organization may choose to have traffic that is inbound to a server go through a specific firewall. In order not to consume the resources of the firewall with clean traffic, the organization may want to choose to redirect the traffic that is outbound from the server to not go through the firewall. Today, zero-trust models are being implemented within the data center; applications and workloads trust no other workload; hence, connectivity between them is not allowed unless explicitly authorized. Each application or workload can have its own security policies. With the advent of cloud networking and multi-tenancy, security policies have evolved to be more workload and application-centric (for example, what type of application, who the tenant is, and which tier of the application is being protected). The SDN Controller must enforce these policies by controlling the forwarding of packets to specific destinations for specific workloads based on the rules provided within the policies.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to forward traffic based on security requirements that have been provided from a security service or policy engine via the northbound API. 

If the SDN Controller is not configured to forward traffic based on security requirements, this is a finding.'
  desc 'fix', 'Configure the SDN controller to forward traffic based on security requirements.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80533r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80797'
  tag rid: 'SV-95507r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001060'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
