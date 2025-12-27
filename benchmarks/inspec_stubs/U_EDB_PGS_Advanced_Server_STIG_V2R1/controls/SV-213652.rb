control 'SV-213652' do
  title 'The EDB Postgres Advanced Server must generate audit records when unsuccessful attempts to delete security objects occur.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an action is attempted, it must be logged.

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
  tag check_id: 'C-14874r290268_chk'
  tag severity: 'medium'
  tag gid: 'V-213652'
  tag rid: 'SV-213652r508024_rule'
  tag stig_id: 'PPS9-00-011500'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag fix_id: 'F-14872r290269_fix'
  tag 'documentable'
  tag legacy: ['SV-83657', 'V-69053']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
