control 'SV-253835' do
  title "The Tanium Server installer's account database permissions must be reduced to an appropriate level."
  desc 'Creating the "tanium" and "tanium_archive" databases through the Tanium Server installer program or using the database to create SQL scripts requires Sysadmin-level permissions. Once the databases have been created, the Tanium Server services must be configured to execute under an account that holds at least the Database Owner (dbo) role on both databases.

Post-installation, if the account used to configure the Tanium Server services to access the remote SQL database server holds only the Database Owner role, rather than the sysadmin role, grant this account the View Server State permission on the SQL Server. This dynamic management view enables the Tanium Server to access data faster than the dbo role alone.'
  desc 'check', '1. Access the Tanium SQL server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open SQL Server Management Studio.

4. Connect to Tanium instance of SQL Server.

5. In the left pane, click "Databases". 

6. Select the Tanium database. 

7. Click "Security". 

8. Click "Users".

9. In the "Users" pane, review the role assigned to the Tanium Server service user account.

10. In the left pane, click "Databases". 

11. Select the Tanium_archive database. 

12. Click "Security". 

13. Click "Users".

14. In the "Users" pane, review the role assigned to the Tanium Server service user account.

15. If the role assigned to the Tanium Server service account is not "db_owner", this is a finding.

16. If using Postgres:

Only owners of objects can change them. To view all functions, triggers, and trigger procedures, and their ownership and source, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -x -c "\\df+"'
  desc 'fix', '1. Access the Tanium SQL server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open SQL Server Management Studio.

4. Connect to Tanium instance of SQL Server.

5. In the left pane, click "Databases". 

6. Select the Tanium database. 

7. Click "Security". 

8. Click "Users". 

9. In the "Users" pane, right-click the Tanium Server service user account.

10. On the shortcut menu, click "Properties".

11. Under Database role membership, change role from "sysadmin" to "db_owner".

12. Click "OK".

13. In the left pane, click "Databases". 

14. Select the Tanium_archive database. 

15. Click "Security". 

16. Click "Users". 

17. In the "Users" pane, right-click the Tanium Server service user account.

18. On the shortcut menu, click "Properties".

19. Under Database role membership, change role from "sysadmin" to "db_owner".

20. Click "OK"

21. If using Postgres:

Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

Use ALTER ROLE to remove accesses from roles:

$ psql -c "ALTER ROLE <role_name> NOSUPERUSER"'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57287r842531_chk'
  tag severity: 'medium'
  tag gid: 'V-253835'
  tag rid: 'SV-253835r850216_rule'
  tag stig_id: 'TANS-DB-000004'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-57238r842532_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
