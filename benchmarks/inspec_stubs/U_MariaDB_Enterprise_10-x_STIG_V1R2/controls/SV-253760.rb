control 'SV-253760' do
  title 'MariaDB must generate audit records when security objects are deleted.'
  desc 'The removal of security objects from the database/DBMS would seriously degrade a system s information assurance posture. If such an event occurs, it must be logged.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

In one terminal, tail the audit log file. For example: 
$ tail -F /var/lib/mysql/server_audit.log (default location)

As the database administrator, create a role by running the following SQL: 
MariaDB>  CREATE ROLE user_role

As the database administrator, delete the user_role: 
MariaDB>  DROP ROLE user_role

If the audit records for DROP are not produced in the first terminal, this is a finding."
  desc 'fix', %q(Super/administrative users must not have access to modify tables within the mysql database. Verify users do not have access and revoke as necessary. Example: 

View user grants:

MariaDB> SHOW GRANTS FOR 'username'@'host';

If user has INSERT, UPDATE, and/or DELETE on the mysql database or all databases, modify the user privileges as necessary. 

The MariaDB Enterprise Audit plugin can be configured to audit these changes. 

Update necessary audit filters to include query_event ALL. Example: 

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event": [
               "CONNECT",
               "DISCONNECT"
            ],
            "query_event": [
                "ALL"
            ]
         }'
      ));)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57212r841803_chk'
  tag severity: 'medium'
  tag gid: 'V-253760'
  tag rid: 'SV-253760r841805_rule'
  tag stig_id: 'MADB-10-010800'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-57163r841804_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
