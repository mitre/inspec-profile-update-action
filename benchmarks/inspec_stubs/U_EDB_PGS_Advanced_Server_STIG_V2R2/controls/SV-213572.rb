control 'SV-213572' do
  title 'The EDB Postgres Advanced Server must produce audit records containing sufficient information to establish where the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. 

Associating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
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
  tag check_id: 'C-14794r290028_chk'
  tag severity: 'medium'
  tag gid: 'V-213572'
  tag rid: 'SV-213572r508024_rule'
  tag stig_id: 'PPS9-00-001800'
  tag gtitle: 'SRG-APP-000097-DB-000041'
  tag fix_id: 'F-14792r290029_fix'
  tag 'documentable'
  tag legacy: ['SV-83503', 'V-68899']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
