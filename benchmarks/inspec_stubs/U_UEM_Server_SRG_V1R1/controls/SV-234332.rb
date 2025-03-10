control 'SV-234332' do
  title 'The UEM server must be configured to produce audit records that contain information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server produces audit records that contain information to establish the outcome of the events.

If the UEM server does not produce audit records that contain information to establish the outcome of the events, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to produce audit records that contain information to establish the outcome of the events.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37517r614006_chk'
  tag severity: 'medium'
  tag gid: 'V-234332'
  tag rid: 'SV-234332r617355_rule'
  tag stig_id: 'SRG-APP-000099-UEM-000059'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-37482r614007_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
