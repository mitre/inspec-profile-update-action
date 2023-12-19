control 'SV-213660' do
  title 'The EDB Postgres Advanced Server must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to the DBMS.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)'
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
  tag check_id: 'C-14882r290292_chk'
  tag severity: 'medium'
  tag gid: 'V-213660'
  tag rid: 'SV-213660r508024_rule'
  tag stig_id: 'PPS9-00-012300'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-14880r290293_fix'
  tag 'documentable'
  tag legacy: ['SV-83673', 'V-69069']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
