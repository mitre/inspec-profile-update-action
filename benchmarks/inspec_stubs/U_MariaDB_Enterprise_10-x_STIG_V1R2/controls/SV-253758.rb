control 'SV-253758' do
  title 'MariaDB must generate audit records when privileges/permissions are deleted.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In MariaDB, deleting permissions is typically done via the REVOKE command.'
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

As the database administrator, add 2 privileges to user_role for testdb and then delete one of the privileges:
MariaDB>  GRANT SELECT,DELETE on testdb to testuser
MariaDB>  GRANT SELECT on testdb to testuser

As the database administrator,  revoke grant from testuser:
MariaDB>  REVOKE user_role to testuser

If the audit records for REVOKE and the second SELECT are not produced in the first terminal, this is a finding."
  desc 'fix', %q(No super/administrative users should not have access to modify tables within the mysql database. Verify users do not have access and revoke as necessary. Example: 

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
  tag check_id: 'C-57210r841797_chk'
  tag severity: 'medium'
  tag gid: 'V-253758'
  tag rid: 'SV-253758r841799_rule'
  tag stig_id: 'MADB-10-010600'
  tag gtitle: 'SRG-APP-000499-DB-000330'
  tag fix_id: 'F-57161r841798_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
