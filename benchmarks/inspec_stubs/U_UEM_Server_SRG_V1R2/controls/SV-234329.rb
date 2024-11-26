control 'SV-234329' do
  title 'The UEM server must be configured to produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time). 

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server produces audit records containing information to establish when (date and time) the events occurred.

If the UEM server does not produce audit records containing information to establish when (date and time) the events occurred, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to produce audit records containing information to establish when (date and time) the events occurred.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37514r613997_chk'
  tag severity: 'medium'
  tag gid: 'V-234329'
  tag rid: 'SV-234329r879564_rule'
  tag stig_id: 'SRG-APP-000096-UEM-000056'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-37479r613998_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
