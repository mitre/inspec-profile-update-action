control 'SV-87749' do
  title 'SDN controllers must be deployed as clusters and on separate physical hosts to eliminate single point of failure.'
  desc 'SDN relies heavily on control messages between a controller and the forwarding devices for network convergence. The controller uses node and link state discovery information to calculate and determine optimum pathing within the SDN network infrastructure based on application, business, and security policies. Operating in the proactive flow instantiation mode, the SDN controller populates forwarding tables to the SDN-aware forwarding devices. At times, the SDN controller must function in reactive flow instantiation mode; that is, when a forwarding device receives a packet for a flow not found in its forwarding table, it must send it to the controller to receive forwarding instructions.

With total dependence on the SDN controller for determining forwarding decisions and path optimization within the SDN infrastructure for both proactive and reactive flow modes of operation, having a single point of failure is not acceptable. A controller failure with no failover backup leaves the network in an unmanaged state. Hence, it is imperative that the SDN controllers are deployed as clusters on separate physical hosts to guarantee network high availability.'
  desc 'check', 'Review the network virtualization platform topology and the SDN configuration to verify that SDN controllers have been deployed as clusters on separate physical hosts. 

If the SDN controllers have not been deployed as clusters on separate physical hosts, this is a finding.'
  desc 'fix', 'Deploy SDN controllers as clusters on separate physical hosts to eliminate single point of failure.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73097'
  tag rid: 'SV-87749r1_rule'
  tag stig_id: 'NET-SDN-013'
  tag gtitle: 'NET-SDN-013'
  tag fix_id: 'F-79543r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
