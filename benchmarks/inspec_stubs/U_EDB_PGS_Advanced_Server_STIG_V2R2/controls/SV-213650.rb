control 'SV-213650' do
  title 'The EDB Postgres Advanced Server must generate audit records when unsuccessful attempts to delete privileges/permissions occur.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict individuals' and groups' privileges could go undetected. 

In an SQL environment, deleting permissions is typically done via the REVOKE command. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
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
  tag check_id: 'C-14872r290262_chk'
  tag severity: 'medium'
  tag gid: 'V-213650'
  tag rid: 'SV-213650r508024_rule'
  tag stig_id: 'PPS9-00-011300'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag fix_id: 'F-14870r290263_fix'
  tag 'documentable'
  tag legacy: ['SV-83653', 'V-69049']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
