control 'SV-206682' do
  title 'The firewall must generate traffic log entries containing information to establish the outcome of the events, such as, at a minimum, the success or failure of the application of the firewall rule.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results. They also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', "Examine the traffic log configuration on the firewall or view several alert events on the organization's central audit server.

Verify the entries sent to the traffic log include sufficient information to ascertain the outcome of the firewall rules. Verify that, at a minimum, the success or failure of the event is evented.

If the traffic log entries do not include sufficient information to ascertain the outcome of the application of the firewall rules, this is a finding.

If the traffic log entries do not include the success or failure of the application of the firewall rules, this is a finding."
  desc 'fix', 'Configure the firewall to generate traffic log entries containing information to establish the outcome of the events, such as, at a minimum, the success or failure of the application of the firewall rule.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6939r297825_chk'
  tag severity: 'medium'
  tag gid: 'V-206682'
  tag rid: 'SV-206682r604133_rule'
  tag stig_id: 'SRG-NET-000078-FW-000013'
  tag gtitle: 'SRG-NET-000078'
  tag fix_id: 'F-6939r297826_fix'
  tag 'documentable'
  tag legacy: ['V-79443', 'SV-94149']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
