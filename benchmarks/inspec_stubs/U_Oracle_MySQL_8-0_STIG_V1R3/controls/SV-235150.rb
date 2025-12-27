control 'SV-235150' do
  title 'The MySQL Database Server 8.0 must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers, and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', %q(Check MySQL settings and documentation to verify that administrative functionality is separate from user functionality.

As Database Administrator (DBA) (“root"), list all roles and permissions for the database:

> mysql -u root -p

SELECT user,host, 'Global Priv', Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv,
    Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv,
    Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv,
    Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv,
    Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,
    Create_routine_priv, Alter_routine_priv, Create_user_priv,
    Event_priv, Trigger_priv, Create_tablespace_priv, Create_role_priv,
    Drop_role_priv 
  FROM mysql.user WHERE 'Y' IN
    (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv,
    Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv,
    Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv,
    Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv,
    Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,
    Create_routine_priv, Alter_routine_priv, Create_user_priv,
    Event_priv, Trigger_priv, Create_tablespace_priv, Create_role_priv,
    Drop_role_priv)
AND user not in ('mysql.infoschema', 'mysql.session');

If any non-administrative role has permissions, other than mysql.infoschema and mysql.session, this is a finding.

If administrator and general user functionality are not separated, this is a finding.)
  desc 'fix', 'Configure MySQL Database Server 8.0 to separate database administration and general user functionality.

Revoke or remove users with admin and user mixed permissions.

Review MySQL documentation related to access controls for users and admins: https://dev.mysql.com/doc/refman/8.0/en/access-control.html.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38369r623570_chk'
  tag severity: 'medium'
  tag gid: 'V-235150'
  tag rid: 'SV-235150r623572_rule'
  tag stig_id: 'MYS8-00-006400'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-38332r623571_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
