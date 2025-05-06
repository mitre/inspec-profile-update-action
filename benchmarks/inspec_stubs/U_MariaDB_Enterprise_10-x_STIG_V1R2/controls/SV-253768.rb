control 'SV-253768' do
  title 'MariaDB must generate audit records showing starting and ending time for user access to the database(s).'
  desc "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to MariaDB lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs. 

Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged."
  desc 'check', 'Log in to and out of the MariaDB database server. Verify the connect and disconnect are logged in the audit logfile or syslog depending on how it is configured. 

If connect and disconnect are not logged, this is a finding.'
  desc 'fix', %q(Edit the necessary filters to include connect_events connect. Example:

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
  tag check_id: 'C-57220r841827_chk'
  tag severity: 'medium'
  tag gid: 'V-253768'
  tag rid: 'SV-253768r841829_rule'
  tag stig_id: 'MADB-10-011600'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-57171r841828_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
