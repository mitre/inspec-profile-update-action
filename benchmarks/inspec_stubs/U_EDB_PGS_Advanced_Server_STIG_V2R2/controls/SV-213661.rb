control 'SV-213661' do
  title 'The EDB Postgres Advanced Server must be able to generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

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
  tag check_id: 'C-14883r290295_chk'
  tag severity: 'medium'
  tag gid: 'V-213661'
  tag rid: 'SV-213661r508024_rule'
  tag stig_id: 'PPS9-00-012400'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag fix_id: 'F-14881r290296_fix'
  tag 'documentable'
  tag legacy: ['SV-83675', 'V-69071']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
