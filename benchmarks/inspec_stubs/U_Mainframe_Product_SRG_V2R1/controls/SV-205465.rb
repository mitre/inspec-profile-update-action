control 'SV-205465' do
  title 'The Mainframe Product must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time). 

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine installation and configuration settings.

Ensure data written to external security manager audit files and/or SMF records contain information that details when events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain information that details when (date and time) the events occurred.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5731r299628_chk'
  tag severity: 'medium'
  tag gid: 'V-205465'
  tag rid: 'SV-205465r395724_rule'
  tag stig_id: 'SRG-APP-000096-MFP-000141'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-5731r299629_fix'
  tag 'documentable'
  tag legacy: ['SV-82733', 'V-68243']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
