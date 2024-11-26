control 'SV-253753' do
  title 'MariaDB must generate audit records when unsuccessful attempts to modify privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected. 

In the MariaDB environment, modifying permissions is typically done via the GRANT, and REVOKE commands. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify query_events includes DCL or ALL in corresponding audit filters. If not, this is a finding.

In one terminal, tail the audit log file. For example: 
$ tail -F /var/lib/mysql/server_audit.log (default location)

Open a new terminal and connect to the database. 

As the database administrator, create a user without special permissions:
MariaDB> CREATE USER 'user_name_here'@'localhost' IDENTIFIED BY 'password_here';

As the database administrator, create a role by running the following SQL: 
MariaDB> CREATE ROLE 'role_name_here';

As the database administrator, GRANT role to testuser: 
MariaDB> GRANT 'role_name_here' TO 'user_name_here'@'localhost';

As the database administrator, add privileges to user_role for testdb, and add GRANT role to testuser:
MariaDB> GRANT SELECT ON db_name_here TO 'user_name_here'@'localhost';
MariaDB> GRANT SELECT ON db_name_here TO 'role_name_here';
 
As a regular user, modify privileges for testuser and user_role:
MariaDB> GRANT DELETE ON db_name_here TO 'user_name_here'@'localhost';
MariaDB> GRANT DELETE ON db_name_here TO 'role_name_here';

If the audit records are not produced for unsuccessful attempts to modify privileges/permissions and roles in the first terminal, this is a finding."
  desc 'fix', %q(The MariaDB Enterprise Audit plugin can be configured to audit these changes. 

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
  tag check_id: 'C-57205r841782_chk'
  tag severity: 'medium'
  tag gid: 'V-253753'
  tag rid: 'SV-253753r841784_rule'
  tag stig_id: 'MADB-10-010100'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-57156r841783_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
