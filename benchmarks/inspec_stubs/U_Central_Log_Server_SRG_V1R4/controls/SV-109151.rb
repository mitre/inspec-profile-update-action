control 'SV-109151' do
  title 'The Central Log Server must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time). 

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server produces audit records containing information to establish when the events occurred.

If the Central Log Server is not configured to produce audit records containing information to establish when the events occurred, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to produce audit records containing information to establish when the events occurred.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98897r1_chk'
  tag severity: 'low'
  tag gid: 'V-100047'
  tag rid: 'SV-109151r1_rule'
  tag stig_id: 'SRG-APP-000096-AU-000690'
  tag gtitle: 'SRG-APP-000096-AU-000690'
  tag fix_id: 'F-105731r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
