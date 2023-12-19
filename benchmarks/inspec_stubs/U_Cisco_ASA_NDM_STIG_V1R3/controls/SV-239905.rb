control 'SV-239905' do
  title 'The Cisco ASA must be configured to produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration should look similar to the example below:

logging enable
logging buffered informational

If the ASA is not configured to generate audit records containing information to establish what type of event occurred, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43138r666076_chk'
  tag severity: 'medium'
  tag gid: 'V-239905'
  tag rid: 'SV-239905r666078_rule'
  tag stig_id: 'CASA-ND-000260'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-43097r666077_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
