control 'SV-224138' do
  title 'The EDB Postgres Advanced Server must initiate support of session auditing upon startup.'
  desc "Session auditing is used when a user's activities are under investigation. To ensure all activity is captured during those periods when session auditing is in use, it must be in operation for the entire time the DBMS is running."
  desc 'check', 'Execute the following SQL as enterprisedb to ensure auditing is enabled:

 SHOW edb_audit;

If the result is not "csv" or "xml", this is a finding.

Execute the following SQL as enterprisedb to check which events are configured to be audited:

 SHOW edb_audit_statement;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', %q(If EDB Auditing is not enabled, execute the following SQL as enterprisedb:

 ALTER SYSTEM SET edb_audit = csv;
 SELECT pg_reload_conf();

or

 ALTER SYSTEM SET edb_audit = xml;
 SELECT pg_reload_conf(); 

If the edb_audit_statement parameter values is not set to "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, execute the following SQL as enterprisedb:

 ALTER SYSTEM SET edb_audit_statement = 'all';
 SELECT pg_reload_conf();

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement.)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25811r495434_chk'
  tag severity: 'medium'
  tag gid: 'V-224138'
  tag rid: 'SV-224138r508023_rule'
  tag stig_id: 'EP11-00-001400'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-25799r495435_fix'
  tag 'documentable'
  tag legacy: ['V-100303', 'SV-109407']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
