control 'SV-213643' do
  title 'The EDB Postgres Advanced Server must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
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
  tag check_id: 'C-14865r290241_chk'
  tag severity: 'medium'
  tag gid: 'V-213643'
  tag rid: 'SV-213643r508024_rule'
  tag stig_id: 'PPS9-00-010800'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-14863r290242_fix'
  tag 'documentable'
  tag legacy: ['V-69039', 'SV-83643']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
