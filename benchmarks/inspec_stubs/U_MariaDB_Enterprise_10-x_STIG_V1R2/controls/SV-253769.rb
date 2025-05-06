control 'SV-253769' do
  title 'MariaDB must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to MariaDB.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)'
  desc 'check', 'Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify connect_events include connect in audit filters. If not, this is a finding.'
  desc 'fix', %q(Edit the necessary filters to include  connect_events connect. Example:

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event":"CONNECT"
         }'
      ));)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57221r841830_chk'
  tag severity: 'medium'
  tag gid: 'V-253769'
  tag rid: 'SV-253769r841832_rule'
  tag stig_id: 'MADB-10-011700'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-57172r841831_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
