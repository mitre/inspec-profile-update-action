control 'SV-224235' do
  title 'The EDB Postgres Advanced Server must generate audit records showing starting and ending time for user access to the database(s) and concurrent logons/connections by the same user from different workstations.'
  desc "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to the DBMS lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.

Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events [logons/connections; voluntary and involuntary disconnections], then it is not mandatory to create additional log entries specifically for this.)

"
  desc 'check', 'Execute the following SQL as enterprisedb:

 SHOW edb_audit_connect;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.

Execute the following SQL as enterprisedb:

 SHOW edb_audit_disconnect;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:

 ALTER SYSTEM SET edb_audit_connect = 'all';
 ALTER SYSTEM SET edb_audit_disconnect = 'all';
 SELECT pg_reload_conf();

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25908r495722_chk'
  tag severity: 'medium'
  tag gid: 'V-224235'
  tag rid: 'SV-224235r508023_rule'
  tag stig_id: 'EP11-00-012200'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-25896r495723_fix'
  tag satisfies: ['SRG-APP-000505-DB-000352', 'SRG-APP-000506-DB-000353']
  tag 'documentable'
  tag legacy: ['SV-109597', 'V-100493']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
