control 'SV-81517' do
  title 'The access to the Tanium SQL database must be restricted. Only the designated database administrator(s) can have elevated privileges to the Tanium SQL database.'
  desc 'After the Tanium Server has been installed and the Tanium databases created, only the Tanium Receiver, Tanium Module, and Tanium connection manager (ad sync) service needs to access the SQL Server database.'
  desc 'check', 'Access the Tanium SQL server interactively.

Log on with an account with administrative privileges to the server.

Open SQL Server Management Studio and connect to a Tanium instance of SQL Server.

In the left pane, click “Databases”, select the Tanium database, click “Security”, and then click “Users”.

In the “Users” pane, review the roles assigned to the user accounts.

If any user account has an elevated privilege role other than the assigned database administrator, this is a finding.'
  desc 'fix', 'Access the Tanium SQL server interactively.

Log on with an account with administrative privileges to the server.

Open SQL Server Management Studio and connect to a Tanium instance of SQL Server.

In the left pane, click “Databases”, select the Tanium database, click “Security”, and then click “Users”.

In the “Users” pane, review the roles assigned to the user accounts.

For any user accounts with elevated privileges, reduce the role assigned to a least privileged role.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67027'
  tag rid: 'SV-81517r1_rule'
  tag stig_id: 'TANS-DB-000003'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-73127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
