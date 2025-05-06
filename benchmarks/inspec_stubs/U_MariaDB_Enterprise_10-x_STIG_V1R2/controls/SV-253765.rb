control 'SV-253765' do
  title 'MariaDB must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to MariaDB. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', 'Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify connect_events include connect in audit filters. If not, this is a finding. 

Log in to and out of the MariaDB database server with both valid and invalid users. Verify the connect and disconnect are logged in the audit logfile or syslog depending on how it is configured. 

If connect/disconnect and invalid logins are not logged, this is a finding.'
  desc 'fix', %q(Edit the necessary filters to include  connect_events connect. Example:

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event": [
               "CONNECT",
               "DISCONNECT"
            ]
         }'
      ));)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57217r841818_chk'
  tag severity: 'medium'
  tag gid: 'V-253765'
  tag rid: 'SV-253765r841820_rule'
  tag stig_id: 'MADB-10-011300'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-57168r841819_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
