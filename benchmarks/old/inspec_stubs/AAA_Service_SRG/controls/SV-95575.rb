control 'SV-95575' do
  title 'AAA Services configuration audit records must identify the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify AAA Services configuration audit records identify the outcome of the events.

If AAA Services configuration audit records do not identify the outcome of the events, this is a finding.'
  desc 'fix', 'Configure AAA Services configuration audit records to identify the outcome of the events.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80865'
  tag rid: 'SV-95575r1_rule'
  tag stig_id: 'SRG-APP-000099-AAA-000260'
  tag gtitle: 'SRG-APP-000099-AAA-000260'
  tag fix_id: 'F-87719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
