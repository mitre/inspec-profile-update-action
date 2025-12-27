control 'SV-213574' do
  title 'The EDB Postgres Advanced Server must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
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
  tag check_id: 'C-14796r290034_chk'
  tag severity: 'medium'
  tag gid: 'V-213574'
  tag rid: 'SV-213574r508024_rule'
  tag stig_id: 'PPS9-00-002000'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag fix_id: 'F-14794r290035_fix'
  tag 'documentable'
  tag legacy: ['SV-83507', 'V-68903']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
