control 'SV-213663' do
  title 'The EDB Postgres Advanced Server must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to the DBMS that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', 'Execute the following SQL as enterprisedb:
	
SHOW edb_audit_statement;
SHOW edb_audit_connect;
SHOW edb_audit_disconnect; 
	
If the result is not "all" for any or if the current settings for this requirement have not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:
	
ALTER SYSTEM SET edb_audit_statement = 'all';
ALTER SYSTEM SET edb_audit_connect = 'all';
ALTER SYSTEM SET edb_audit_disconnect = 'all';
SELECT pg_reload_conf();   
	
or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14885r290301_chk'
  tag severity: 'medium'
  tag gid: 'V-213663'
  tag rid: 'SV-213663r508024_rule'
  tag stig_id: 'PPS9-00-012600'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-14883r290302_fix'
  tag 'documentable'
  tag legacy: ['V-69075', 'SV-83679']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
