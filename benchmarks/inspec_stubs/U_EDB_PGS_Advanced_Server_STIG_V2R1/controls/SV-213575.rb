control 'SV-213575' do
  title 'The EDB Postgres Advanced Server must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW edb_audit_statement;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:
	
ALTER SYSTEM SET edb_audit_statement = 'all';
SELECT pg_reload_conf();

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14797r290037_chk'
  tag severity: 'medium'
  tag gid: 'V-213575'
  tag rid: 'SV-213575r508024_rule'
  tag stig_id: 'PPS9-00-002100'
  tag gtitle: 'SRG-APP-000100-DB-000201'
  tag fix_id: 'F-14795r290038_fix'
  tag 'documentable'
  tag legacy: ['SV-83509', 'V-68905']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
