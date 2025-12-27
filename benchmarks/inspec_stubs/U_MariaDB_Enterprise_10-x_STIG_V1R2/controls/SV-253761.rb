control 'SV-253761' do
  title 'MariaDB must generate audit records when unsuccessful attempts to delete security objects occur.'
  desc 'The removal of security objects from the database/DBMS would seriously degrade a system s information assurance posture. If such an action is attempted, it must be logged.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

As the database administrator, create a user without special permissions:
MariaDB>  CREATE USER testuser IDENTIFIED BY  password ;

In one terminal, tail the audit log file. For example: 
$ tail -F /var/lib/mysql/server_audit.log (default location)

As the database administrator, create a role by running the following SQL: 
MariaDB>  CREATE ROLE user_role

As the database administrator, GRANT user_role to testuser: 
MariaDB>  GRANT user_role to testuser

As the database administrator, add two privileges to user_role for testdb and then delete one of the privileges:
MariaDB>  GRANT SELECT,DELETE on testdb to testuser
MariaDB>  GRANT SELECT on testdb to testuser

As the database administrator, revoke grant from testuser:
MariaDB>  REVOKE user_role to testuser

If the audit records for REVOKE and the second SELECT are not produced in the first terminal, this is a finding."
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
  tag check_id: 'C-57213r841806_chk'
  tag severity: 'medium'
  tag gid: 'V-253761'
  tag rid: 'SV-253761r841808_rule'
  tag stig_id: 'MADB-10-010900'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag fix_id: 'F-57164r841807_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
