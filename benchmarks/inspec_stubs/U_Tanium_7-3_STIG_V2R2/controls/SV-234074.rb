control 'SV-234074' do
  title 'The Tanium Server installers account database permissions must be reduced to an appropriate level.'
  desc 'Creating the tanium and tanium_archive databases through the Tanium Server installer program or using the database create SQL scripts requires Sysadmin-level permissions. Once the databases have been created, the Tanium Server and Apache services must be configured to execute under an account that holds at least the dbo role on both databases.

Post-installation, if the account used to configure the Tanium Server services to access the remote SQL database server holds only the Database Owner role, rather than the sysadmin role, consider granting this account the View Server State permission on the SQL Server. While not strictly necessary, this dynamic management view enables the Tanium Server to access data faster than the dbo role alone.'
  desc 'check', 'Access the Tanium SQL server interactively.

Log on to the server with an account that has administrative privileges.

Open SQL Server Management Studio.

Connect to Tanium instance of SQL Server.

In the left pane, click "Databases". 

Select the Tanium database. 

Click "Security". 

Click "Users".

In the "Users" pane, review the role assigned to the Tanium Server service user account.

If the role assigned to the Tanium Server service account is not "db_owner", this is a finding.

If using Postgres:

Only owners of objects can change them. To view all functions, triggers, and trigger procedures, their ownership and source, as the database administrator (shown here as "postgres") run the following SQL:

$ sudo su - postgres
$ psql -x -c "\\df+"'
  desc 'fix', 'Access the Tanium SQL server interactively.

Log on to the server with an account that has administrative privileges.

Open SQL Server Management Studio.

Connect to Tanium instance of SQL Server.

In the left pane, click "Databases". 

Select the Tanium database. 

Click "Security". 

Click "Users". 

In the "Users" pane, right-click the Tanium Server service user account.

On the shortcut menu, click "Properties".

Under Database role membership, change role from "sysadmin" to "db_owner".

Click "OK".

If using Postgres:

Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

Use ALTER ROLE to remove accesses from roles:

$ psql -c "ALTER ROLE <role_name> NOSUPERUSER"'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37259r610722_chk'
  tag severity: 'medium'
  tag gid: 'V-234074'
  tag rid: 'SV-234074r612749_rule'
  tag stig_id: 'TANS-DB-000004'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-37224r610723_fix'
  tag 'documentable'
  tag legacy: ['SV-102221', 'V-92119']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
