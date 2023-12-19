control 'SV-222473' do
  title 'The application must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).'
  desc 'check', 'Access the application logs and review the log entries for date and time. Each event written into the log must have a corresponding date and time stamp associated with it.

If the audit logs do not have a corresponding date and time associated with each event, this is a finding.'
  desc 'fix', 'Configure the application or application server to include the date and the time of the event in the audit logs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24143r493327_chk'
  tag severity: 'medium'
  tag gid: 'V-222473'
  tag rid: 'SV-222473r879564_rule'
  tag stig_id: 'APSC-DV-000980'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-24132r493328_fix'
  tag 'documentable'
  tag legacy: ['V-69429', 'SV-84051']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
