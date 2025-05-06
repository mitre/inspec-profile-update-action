control 'SV-213570' do
  title 'The EDB Postgres Advanced Server must produce audit records containing sufficient information to establish what type of events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.'
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
  tag check_id: 'C-14792r290022_chk'
  tag severity: 'medium'
  tag gid: 'V-213570'
  tag rid: 'SV-213570r508024_rule'
  tag stig_id: 'PPS9-00-001600'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag fix_id: 'F-14790r290023_fix'
  tag 'documentable'
  tag legacy: ['V-68895', 'SV-83499']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
