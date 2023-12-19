control 'SV-206533' do
  title 'The DBMS must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Check DBMS settings and existing audit records to verify a user name associated with the event is being captured and stored with the audit records. If audit records exist without specific user information, this is a finding.'
  desc 'fix', 'Configure DBMS audit settings to include user name as part of the audit record.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6793r291267_chk'
  tag severity: 'medium'
  tag gid: 'V-206533'
  tag rid: 'SV-206533r617447_rule'
  tag stig_id: 'SRG-APP-000100-DB-000201'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-6793r291268_fix'
  tag 'documentable'
  tag legacy: ['SV-42711', 'V-32374']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
