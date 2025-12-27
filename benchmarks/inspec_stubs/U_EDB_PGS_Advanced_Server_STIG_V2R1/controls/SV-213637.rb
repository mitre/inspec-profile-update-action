control 'SV-213637' do
  title 'The EDB Postgres Advanced Server must generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE'
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
  tag check_id: 'C-14859r290223_chk'
  tag severity: 'medium'
  tag gid: 'V-213637'
  tag rid: 'SV-213637r508024_rule'
  tag stig_id: 'PPS9-00-010000'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-14857r290224_fix'
  tag 'documentable'
  tag legacy: ['SV-83631', 'V-69027']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
