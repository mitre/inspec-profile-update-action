control 'SV-213569' do
  title 'The EDB Postgres Advanced Server must initiate support of session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. 

Typically, this DBMS capability would be used in conjunction with comparable monitoring of a user's online session, involving other software components such as operating systems, web servers and front-end user applications. The current requirement, however, deals specifically with the DBMS.

To be sure of capturing all activity during those periods when session auditing is in use, database auditing needs to be in operation for the whole time the DBMS is running."
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
  tag check_id: 'C-14791r290019_chk'
  tag severity: 'medium'
  tag gid: 'V-213569'
  tag rid: 'SV-213569r508024_rule'
  tag stig_id: 'PPS9-00-001400'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-14789r290020_fix'
  tag 'documentable'
  tag legacy: ['V-68891', 'SV-83495']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
