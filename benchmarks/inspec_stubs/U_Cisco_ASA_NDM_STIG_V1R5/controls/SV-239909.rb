control 'SV-239909' do
  title 'The Cisco ASA must be configured to produce audit records that contain information to establish the outcome of the event.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration should look similar to the example below:

logging enable
logging buffered informational
 
If the ASA is not configured to generate audit records containing information to establish the outcome of the event, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43142r666088_chk'
  tag severity: 'medium'
  tag gid: 'V-239909'
  tag rid: 'SV-239909r879567_rule'
  tag stig_id: 'CASA-ND-000300'
  tag gtitle: 'SRG-APP-000099-NDM-000229'
  tag fix_id: 'F-43101r666089_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
