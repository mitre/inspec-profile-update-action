control 'SV-81519' do
  title 'The Tanium Server installers account SQL database permissions must be reduced from sysadmin to db_owner.'
  desc "Creating the tanium and tanium_archive databases through the Tanium Server installer program or using the database create SQL scripts requires Sysadmin-level permissions. Once the databases have been created, the Tanium Server service must be configured to execute under an account that holds at least the dbo role on both databases.

Post-installation, if the account used to configure the Tanium Server services to access the remote SQL database server holds only the Database Owner role, rather than the sysadmin role, consider granting this account the View Server State permission on the SQL Server. While it's not strictly necessary, this dynamic management view enables the Tanium Server to access data faster than the dbo role alone."
  desc 'check', "Access the Tanium SQL server interactively.

Log on with an account with administrative privileges to the server.

Open SQL Server Management Studio and connect to Tanium instance of SQL Server.

In the left pane, click “Databases”, select the Tanium database, click “Security”, and then click “Users”.

In the “Users” pane, review the role assign to the Tanium Server installer's user account.

If the role assigned to the Tanium Server installer's account is not db_owner, this is a finding."
  desc 'fix', "Access the Tanium SQL server interactively.

Log on with an account with administrative privileges to the server.

Open SQL Server Management Studio and connect to Tanium instance of SQL Server.

In the left pane, click “Databases”, select the Tanium database, click “Security”, and then click “Users”.

In the “Users” pane, right-click the Tanium Server installer's user account, and on the shortcut menu, click “Properties”.

Under Database role membership, change role from sysadmin to db_owner.

Click “OK”."
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67665r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67029'
  tag rid: 'SV-81519r1_rule'
  tag stig_id: 'TANS-DB-000004'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-73129r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
