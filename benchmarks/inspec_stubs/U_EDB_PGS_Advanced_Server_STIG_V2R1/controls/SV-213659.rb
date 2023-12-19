control 'SV-213659' do
  title 'The EDB Postgres Advanced Server must generate audit records showing starting and ending time for user access to the database(s).'
  desc "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to the DBMS lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs. 

Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged."
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW edb_audit_connect;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:

ALTER SYSTEM SET edb_audit_connect = 'all';
ALTER SYSTEM SET edb_audit_disconnect = 'all';
SELECT pg_reload_conf();   

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14881r290289_chk'
  tag severity: 'medium'
  tag gid: 'V-213659'
  tag rid: 'SV-213659r508024_rule'
  tag stig_id: 'PPS9-00-012200'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-14879r290290_fix'
  tag 'documentable'
  tag legacy: ['SV-83671', 'V-69067']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
