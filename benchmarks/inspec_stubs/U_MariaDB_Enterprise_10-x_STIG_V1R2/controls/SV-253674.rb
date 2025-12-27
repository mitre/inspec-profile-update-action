control 'SV-253674' do
  title 'MariaDB must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it must be in operation for the whole time MariaDB is running."
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Check what filters are in place for user by running the following as an administrative user: 

MariaDB> SELECT sau.host, sau.user, saf.filtername,
   JSON_DETAILED(saf.rule)
FROM mysql.server_audit_filters saf
JOIN mysql.server_audit_users sau
   ON saf.filtername = sau.filtername
WHERE saf.filtername != 'default'\\G

Verify the corresponding audit filters are in place. If not, this is a finding."
  desc 'fix', %q(If not already exists, create a named filter with the required auditing for the user in question. Example: 

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('session_auditing',
      JSON_COMPACT(
         '{
            "connect_event": [
               "CONNECT",
               "DISCONNECT"
            ],
            "table_event":[
               "WRITE",
               "CREATE",
               "DROP",
               "RENAME",
               "ALTER"
            ]
         }'
      ));

Then assign the named filter to the user. Example:

MariaDB> INSERT INTO mysql.server_audit_users (host, user, filtername) VALUES ("%", "username", "session_auditing");

Reload filters. 

MariaDB> SET GLOBAL server_audit_reload_filters = ON;)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57126r841545_chk'
  tag severity: 'medium'
  tag gid: 'V-253674'
  tag rid: 'SV-253674r841547_rule'
  tag stig_id: 'MADB-10-000900'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-57077r841546_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
