control 'SV-234073' do
  title 'The access to the Tanium SQL database must be restricted. Only the designated database administrator(s) can have elevated privileges to the Tanium SQL database.'
  desc 'After the Tanium Server has been installed and the Tanium databases created, only the Tanium Receiver, Tanium Module, and Tanium connection manager (ad sync) service needs to access the SQL Server database.'
  desc 'check', 'Access the Tanium SQL server interactively.

Log on to the server with an account that has administrative privileges.

Open SQL Server Management Studio.

Connect to a Tanium instance of SQL Server.

In the left pane, click "Databases". 

Select the Tanium database. 

Click "Security". 

Click "Users".

In the "Users" pane, review the roles assigned to the user accounts. (Note: This does not apply to service accounts.)

If any user account has an elevated privilege role other than the assigned database administrators, this is a finding.'
  desc 'fix', 'Access the Tanium SQL server interactively.

Log on to the server with an account that has administrative privileges.

Open SQL Server Management Studio.

Connect to a Tanium instance of SQL Server.

In the left pane, click "Databases". 

Select the Tanium database. 

Click "Security". 

Click "Users".

In the "Users" pane, review the roles assigned to the user accounts.

For any user accounts with elevated privileges, reduce the role assigned to a least privileged role.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37258r610719_chk'
  tag severity: 'medium'
  tag gid: 'V-234073'
  tag rid: 'SV-234073r612749_rule'
  tag stig_id: 'TANS-DB-000003'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-37223r610720_fix'
  tag 'documentable'
  tag legacy: ['SV-102219', 'V-92117']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
