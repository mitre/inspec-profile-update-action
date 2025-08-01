control 'SV-87753' do
  title 'SDN-enabled routers and switches must rate limit the amount of unknown data plane packets that are punted to the SDN controller.'
  desc 'SDN-enabled forwarding devices are dependent on the SDN controller for their forwarding tables as well as their configuration and service parameters. The controller uses node and link state discovery information to calculate and determine optimum pathing within the SDN network infrastructure based on application, business, and security policies. Operating in the proactive flow instantiation mode, the SDN controller pre-populates forwarding tables to the forwarding devices. 

At times, the SDN controller must function in reactive flow instantiation mode; that is, when a forwarding device receives a packet for a flow not found in its forwarding table, it must send or punt it to the controller to receive forwarding instructions. Upon receiving the punted packet, the controller must determine how to forward the packet, create a rule, and populate a new forwarding table to the forwarding device. High rates of punted packets result in excessive controller CPU and memory utilization. Hence, a denial-of-serve attack targeting the SDN controller can be perpetrated either inadvertently or maliciously, involving high rates of packets for new flows that must be punted to the controller.'
  desc 'check', 'Review the parameters provided by the SDN manager or controller when deploying router or switch instances to determine if they set a threshold on the number of unknown data plane packets that are allowed to be punted by a virtual router or switch to the controller within a specific amount of time. 

Review the configuration of all physical SDN-enabled switches and routers and verify that packet-in messages are rate limited. 

If SDN-enabled routers and switches do not rate limit the amount of unknown data plane packets that are punted to the SDN controller, this is a finding.'
  desc 'fix', 'Configure the SDN manager or controller to set a threshold on the number of unknown data plane packets that are allowed to be punted by a virtual router or switch to the controller within a specific amount of time. 

Configure all physical SDN-enabled switches and routers to rate limit the amount of packets that are punted to the SDN controller.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73235r1_chk'
  tag severity: 'low'
  tag gid: 'V-73101'
  tag rid: 'SV-87753r1_rule'
  tag stig_id: 'NET-SDN-015'
  tag gtitle: 'NET-SDN-015'
  tag fix_id: 'F-79547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
