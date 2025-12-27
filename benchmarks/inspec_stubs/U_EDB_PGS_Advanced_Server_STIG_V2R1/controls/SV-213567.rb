control 'SV-213567' do
  title 'The EDB Postgres Advanced Server must generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
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
  tag check_id: 'C-14789r290013_chk'
  tag severity: 'medium'
  tag gid: 'V-213567'
  tag rid: 'SV-213567r508024_rule'
  tag stig_id: 'PPS9-00-001200'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-14787r290014_fix'
  tag 'documentable'
  tag legacy: ['SV-83491', 'V-68887']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
