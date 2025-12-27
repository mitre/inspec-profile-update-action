control 'SV-87751' do
  title 'Physical devices hosting an SDN controller must be connected to two switches for high-availability.'
  desc 'SDN relies heavily on control messages between a controller and the forwarding devices for network convergence. The controller uses node and link state discovery information to calculate and determine optimum pathing within the SDN network infrastructure based on application, business, and security policies. Operating in the proactive flow instantiation mode, the SDN controller populates forwarding tables to the SDN-aware forwarding devices. At times, the SDN controller must function in reactive flow instantiation mode; that is, when a forwarding device receives a packet for a flow not found in its forwarding table, it must send it to the controller to receive forwarding instructions.

With total dependence on the SDN controller for determining forwarding decisions and path optimization within the SDN infrastructure for both proactive and reactive flow modes of operation, having a single point of failure is not acceptable. Hence, it is imperative that all physical devices hosting an SDN controller are connected to two switches using NIC teaming to guarantee network high availability.'
  desc 'check', 'Review the network topology as well as the physical connection between the physical device hosting an SDN controller and the switches. 

The device must have NIC teaming enabled and must be dual homed, with each upstream link connected to a different switch. 

If the physical device hosting an SDN controller is not connected to two switches using NIC teaming, this is a finding.'
  desc 'fix', 'Enable NIC teaming on the device hosting an SDN controller in either Link Aggregation Control Protocol (LACP) or switch-independent mode. 

Connect each interface to a different access switch.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73233r1_chk'
  tag severity: 'low'
  tag gid: 'V-73099'
  tag rid: 'SV-87751r1_rule'
  tag stig_id: 'NET-SDN-014'
  tag gtitle: 'NET-SDN-014'
  tag fix_id: 'F-79545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
