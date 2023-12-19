control 'SV-87755' do
  title 'Servers hosting SDN controllers must have logging enabled.'
  desc 'It is critical for both network and security personnel to be aware of the state of the SDN infrastructure to maintain network stability. Associating logged events that have occurred within the SDN controller as well as network state information provided by the SDN-enabled components is essential to compile an accurate risk assessment and troubleshoot network outages.'
  desc 'check', 'Review all servers hosting an SDN controller and verify that logging has been enabled. 

If logging is not enabled on all servers hosting an SDN controller, this is a finding.'
  desc 'fix', 'Enable logging on all servers hosting an SDN controller.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73237r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73103'
  tag rid: 'SV-87755r1_rule'
  tag stig_id: 'NET-SDN-016'
  tag gtitle: 'NET-SDN-016'
  tag fix_id: 'F-79549r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001846']
  tag nist: ['AU-3 (2)']
end
