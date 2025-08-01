control 'SV-213571' do
  title 'The EDB Postgres Advanced Server must produce audit records containing time stamps to establish when the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the date and time when events occurred.

Associating the date and time with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly when specific actions were performed. This requires the date and time an audit record is referring to. If date and time information is not recorded and stored with the audit record, the record itself is of very limited use.'
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
  tag check_id: 'C-14793r290025_chk'
  tag severity: 'medium'
  tag gid: 'V-213571'
  tag rid: 'SV-213571r508024_rule'
  tag stig_id: 'PPS9-00-001700'
  tag gtitle: 'SRG-APP-000096-DB-000040'
  tag fix_id: 'F-14791r290026_fix'
  tag 'documentable'
  tag legacy: ['V-68897', 'SV-83501']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
