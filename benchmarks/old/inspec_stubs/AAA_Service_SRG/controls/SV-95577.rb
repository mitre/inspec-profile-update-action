control 'SV-95577' do
  title 'AAA Services configuration audit records must identify any individual user or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Verify AAA Services configuration audit records identify any individual user associated with the event. When a system process rather than an individual user causes the event, the process must be identified in the audit record.

If AAA Services configuration audit records do not identify any individual user or process associated with the event, this is a finding.'
  desc 'fix', 'Configure AAA Services configuration audit records to identify any individual user associated with the event. When events are caused by a system process rather than an individual user, that process must be identified in the audit record.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80603r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80867'
  tag rid: 'SV-95577r1_rule'
  tag stig_id: 'SRG-APP-000100-AAA-000270'
  tag gtitle: 'SRG-APP-000100-AAA-000270'
  tag fix_id: 'F-87721r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
