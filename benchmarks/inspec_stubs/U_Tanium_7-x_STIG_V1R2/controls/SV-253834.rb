control 'SV-253834' do
  title 'The access to the Tanium SQL database must be restricted. Only the designated database administrator(s) can have elevated privileges to the Tanium SQL database.'
  desc 'After the Tanium Server has been installed and the Tanium databases created, only the Tanium Server needs to access the SQL Server database.'
  desc 'check', '1. Access the Tanium SQL server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open SQL Server Management Studio.

4. Connect to a Tanium instance of SQL Server.

5. In the left pane, click "Databases". 

6. Select the Tanium database. 

7. Click "Security". 

8. Click "Users".

9. In the "Users" pane, review the roles assigned to the user accounts. (Note: This does not apply to service accounts.)

10. Select the Tanium_archive database. 

11. Click "Security". 

12. Click "Users".

13. In the "Users" pane, review the roles assigned to the user accounts. (Note: This does not apply to service accounts.)

If any user account has an elevated privilege role other than the assigned database administrators, this is a finding.'
  desc 'fix', '1. Access the Tanium SQL server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open SQL Server Management Studio.

4. Connect to a Tanium instance of SQL Server.

5. In the left pane, click "Databases". 

6. Select the Tanium database. 

7. Click "Security". 

8. Click "Users".

9. In the "Users" pane, review the roles assigned to the user accounts. (Note: This does not apply to service accounts.)

10. Select the Tanium_archive database. 

11. Click "Security". 

12. Click "Users".

13. Adjust user roles as necessary. (Note: This does not apply to service accounts.)'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57286r842528_chk'
  tag severity: 'medium'
  tag gid: 'V-253834'
  tag rid: 'SV-253834r850216_rule'
  tag stig_id: 'TANS-DB-000003'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-57237r842529_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
