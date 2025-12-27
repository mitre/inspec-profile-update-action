control 'SV-221912' do
  title 'The Central Log Server must produce audit records that contain information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server produces audit records containing information to establish the outcome of the events.

If the Central Log Server is not configured to produce audit records containing information to establish the outcome of the events, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to produce audit records containing information to establish the outcome of the events.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23627r420078_chk'
  tag severity: 'low'
  tag gid: 'V-221912'
  tag rid: 'SV-221912r420080_rule'
  tag stig_id: 'SRG-APP-000099-AU-000720'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-23616r420079_fix'
  tag 'documentable'
  tag legacy: ['SV-109157', 'V-100053']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
