control 'SV-213627' do
  title 'The EDB Postgres Advanced Server must produce audit records of its enforcement of access restrictions associated with changes to the configuration of the EDB Postgres Advanced Server or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
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
  tag check_id: 'C-14849r290193_chk'
  tag severity: 'medium'
  tag gid: 'V-213627'
  tag rid: 'SV-213627r508024_rule'
  tag stig_id: 'PPS9-00-008600'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-14847r290194_fix'
  tag 'documentable'
  tag legacy: ['SV-83611', 'V-69007']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
