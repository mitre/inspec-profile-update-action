control 'SV-213638' do
  title 'The EDB Postgres Advanced Server must generate audit records when unsuccessful attempts to access security objects occur.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE

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
  tag check_id: 'C-14860r290226_chk'
  tag severity: 'medium'
  tag gid: 'V-213638'
  tag rid: 'SV-213638r508024_rule'
  tag stig_id: 'PPS9-00-010100'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag fix_id: 'F-14858r290227_fix'
  tag 'documentable'
  tag legacy: ['SV-83633', 'V-69029']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
