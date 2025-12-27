control 'SV-213644' do
  title 'The EDB Postgres Advanced Server must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
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
  tag check_id: 'C-14866r290244_chk'
  tag severity: 'medium'
  tag gid: 'V-213644'
  tag rid: 'SV-213644r508024_rule'
  tag stig_id: 'PPS9-00-010900'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-14864r290245_fix'
  tag 'documentable'
  tag legacy: ['SV-83645', 'V-69041']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
