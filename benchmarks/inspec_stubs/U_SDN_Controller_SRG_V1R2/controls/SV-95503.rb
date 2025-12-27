control 'SV-95503' do
  title 'The SDN controller must be configured to be deployed as a cluster and on separate physical hosts.'
  desc 'SDN relies heavily on control messages between a controller and the forwarding devices for network convergence. The controller uses node and link state discovery information to calculate and determine optimum pathing within the SDN network infrastructure based on application, business, and security policies. Operating in the proactive flow instantiation mode, the SDN controller populates forwarding tables to the SDN-aware forwarding devices. At times, the SDN controller must function in reactive flow instantiation mode; that is, when a forwarding device receives a packet for a flow not found in its forwarding table, it must send it to the controller to receive forwarding instructions.

With total dependence on the SDN controller for determining forwarding decisions and path optimization within the SDN infrastructure for both proactive and reactive flow modes of operation, having a single point of failure is not acceptable. A controller failure with no failover backup leaves the network in an unmanaged state. Hence, it is imperative that the SDN controllers are deployed as clusters on separate physical hosts to guarantee network high availability.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to peer with one or more controllers. Also verify that the controller resides on a different physical host than any of its peers. 

If the SDN controller is not configured to be deployed as a cluster and on separate physical hosts, this is a finding.'
  desc 'fix', 'Deploy the SDN controller as a cluster using on a separate physical hosts to eliminate single point of failure. Configure the SDN controller to peer with one or more controllers.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80529r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80793'
  tag rid: 'SV-95503r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001050'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
