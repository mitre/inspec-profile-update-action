control 'SV-95477' do
  title 'The SDN controller must be configured to produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network. Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Review the SDN controller configuration to determine if the audit records will note the outcome (i.e. packet allowed, packet dropped, link down, etc.) the event that is being logged. 

If the SDN controller is not configured to produce audit records containing information to establish the outcome (i.e. packet allowed, packet dropped, link down, etc.) of the events, this is a finding.'
  desc 'fix', 'Configure the SDN controller to include the outcome (i.e. packet allowed, packet dropped, link down, etc.) of the event in the log records.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80503r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80767'
  tag rid: 'SV-95477r1_rule'
  tag stig_id: 'SRG-NET-000078-SDN-000140'
  tag gtitle: 'SRG-NET-000078'
  tag fix_id: 'F-87621r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
