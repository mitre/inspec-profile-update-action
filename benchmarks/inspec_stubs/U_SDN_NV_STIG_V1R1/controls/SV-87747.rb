control 'SV-87747' do
  title 'Quality of service (QoS) must be implemented on the underlying IP network to provide preferred treatment for traffic between the SDN controllers and SDN-enabled switches and hypervisors.'
  desc 'With the network topology abstraction, the SDN controllers are able to determine how traffic should flow through network devices based on application data, business policy, bandwidth, and path availability. When updated link state information is provided by the network elements, the SDN controller must recalculate the optimized paths for network reconvergence and provide the new forwarding tables to the network elements. 

When network congestion occurs, all traffic has an equal chance of being dropped. QoS provisioning categorizes network traffic, prioritizes it according to its relative importance, and provides preferential treatment using various priority queuing techniques. Prioritization of both link state updates and control plane traffic must be implemented to verify that during periods of severe network congestion, the network can converge.'
  desc 'check', 'Note: This requirement will not be applicable if an out-of-band network is used to transport SDN control and management plane traffic.

Review the router and multilayer switch configurations to verify that SDN control and management plane packets are receiving the appropriate amount of priority to ensure this traffic has preference over normal production traffic. 

If not all routers and multilayer switches impose preferred treatment for SDN control and management plane traffic during periods of congestion, this is a finding.'
  desc 'fix', 'Determine the paths in which SDN control and management plane traffic will flow between the SDN controllers and SDN-enabled switches and routers. 

Configure each router and multilayer switch to impose preferred treatment for this traffic so it has priority over normal production traffic during periods of congestion.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73229r3_chk'
  tag severity: 'low'
  tag gid: 'V-73095'
  tag rid: 'SV-87747r1_rule'
  tag stig_id: 'NET-SDN-012'
  tag gtitle: 'NET-SDN-012'
  tag fix_id: 'F-79541r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
