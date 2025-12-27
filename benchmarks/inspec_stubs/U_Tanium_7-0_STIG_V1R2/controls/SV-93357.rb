control 'SV-93357' do
  title 'The Tanium Server installers account SQL database permissions must be reduced from sysadmin to db_owner.'
  desc 'Creating the tanium and tanium_archive databases through the Tanium Server installer program or using the database create SQL scripts requires Sysadmin-level permissions. Once the databases have been created, the Tanium Server and Apache services must be configured to execute under an account that holds at least the dbo role on both databases.

Post-installation, if the account used to configure the Tanium Server services to access the remote SQL database server holds only the Database Owner role, rather than the sysadmin role, consider granting this account the View Server State permission on the SQL Server. While it is not strictly necessary, this dynamic management view enables the Tanium Server to access data faster than the dbo role alone.'
  desc 'check', 'Access the Tanium SQL server interactively.

Log on with an account with administrative privileges to the server.

Open SQL Server Management Studio and connect to a Tanium instance of SQL Server.

In the left pane, click "Databases".
Select the Tanium database.
Click "Security".
Click "Users".

In the "Users" pane, review the role assigned to the Tanium Server service user account.

If the role assigned to the Tanium Server service account is not db_owner, this is a finding.'
  desc 'fix', 'Access the Tanium SQL server interactively.

Log on with an account with administrative privileges to the server.

Open SQL Server Management Studio and connect to Tanium instance of SQL Server.

In the left pane, click "Databases".
Select the Tanium database.
Click "Security".
Click "Users".

In the "Users" pane, right-click the Tanium Server service user account, and on the shortcut menu, click "Properties".

Under Database role membership, change role from sysadmin to db_owner.

Click "OK".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78651'
  tag rid: 'SV-93357r1_rule'
  tag stig_id: 'TANS-DB-000004'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-85387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
