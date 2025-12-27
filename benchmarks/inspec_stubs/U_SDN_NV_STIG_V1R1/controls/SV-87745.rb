control 'SV-87745' do
  title 'SDN-enabled routers and switches must provide link state information to the SDN controller to create new forwarding decisions for the network elements.'
  desc 'Southbound APIs such as OpenFlow provide the forwarding tables to network devices such as switches and routers. SDN controllers have an abstraction of the network topology based on discovery and provisioning information provided by management and orchestration systems. 

The SDN controllers use the concept of flows to identify network traffic based on predefined rules that can be statically or dynamically programmed by the SDN control software. With the network topology abstraction, they are able to determine how traffic should flow through network devices based on application data, business policy, bandwidth, and path availability. If the SDN-enabled network elements do not provide updated link state information, the SDN controller is not able to reconverge the network to verify there is reachability to all destinations.'
  desc 'check', 'Review the configurations for all SDN-enabled routers and switches and verify that link state information is provided to the SDN controllers. 

If the SDN-enabled routers and switches do not provide link state information to the SDN controllers, this is a finding.

Note: This requirement is not applicable if the SDN deployment model does not rely on the controller for network forwarding or convergence.'
  desc 'fix', 'Configure all SDN-enabled routers and switches to send link state information to the SDN controllers.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73227r1_chk'
  tag severity: 'low'
  tag gid: 'V-73093'
  tag rid: 'SV-87745r1_rule'
  tag stig_id: 'NET-SDN-011'
  tag gtitle: 'NET-SDN-011'
  tag fix_id: 'F-79539r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
