control 'SV-213641' do
  title 'The EDB Postgres Advanced Server must generate audit records when privileges/permissions are added.'
  desc "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of individuals' and groups' privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the REVOKE command."
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
  tag check_id: 'C-14863r290235_chk'
  tag severity: 'medium'
  tag gid: 'V-213641'
  tag rid: 'SV-213641r508024_rule'
  tag stig_id: 'PPS9-00-010400'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag fix_id: 'F-14861r290236_fix'
  tag 'documentable'
  tag legacy: ['SV-83639', 'V-69035']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
