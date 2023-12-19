control 'SV-213651' do
  title 'The EDB Postgres Advanced Server must generate audit records when security objects are deleted.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged."
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
  tag check_id: 'C-14873r290265_chk'
  tag severity: 'medium'
  tag gid: 'V-213651'
  tag rid: 'SV-213651r508024_rule'
  tag stig_id: 'PPS9-00-011400'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-14871r290266_fix'
  tag 'documentable'
  tag legacy: ['SV-83655', 'V-69051']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
