control 'SV-205468' do
  title 'The Mainframe Product must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Examine installation and configuration settings.

Verify data written to external security manager audit files and/or SMF records contain information that details the outcome of events. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain information to establish the outcome of the events.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5734r299637_chk'
  tag severity: 'medium'
  tag gid: 'V-205468'
  tag rid: 'SV-205468r395733_rule'
  tag stig_id: 'SRG-APP-000099-MFP-000144'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-5734r299638_fix'
  tag 'documentable'
  tag legacy: ['SV-82739', 'V-68249']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
