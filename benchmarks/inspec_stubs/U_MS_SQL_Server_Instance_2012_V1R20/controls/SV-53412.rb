control 'SV-53412' do
  title 'SQL Server default account sa must have its name changed.'
  desc "SQL Server's 'sa' account has special privileges required to administer the database. The 'sa' account is a well-known SQL Server account name and is likely to be targeted by attackers, and is thus more prone to providing unauthorized access to the database.

Since the SQL Server 'sa' is administrative in nature, the compromise of a default account can have catastrophic consequences, including the complete loss of control over SQL Server. Since SQL Server needs for this account to exist and it should not be removed, one way to mitigate this risk is to change the 'sa' account name."
  desc 'check', "Verify the SQL Server default 'sa' account name has been changed.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins.

If SQL Server default 'sa' account name is in the 'Logins' list, this is a finding."
  desc 'fix', "Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> click 'sa' account name.

Hit <F2> while the name is highlighted in order to edit the name.

Rename the 'sa' account."
  impact 0.3
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47654r2_chk'
  tag severity: 'low'
  tag gid: 'V-41037'
  tag rid: 'SV-53412r2_rule'
  tag stig_id: 'SQL2-00-010200'
  tag gtitle: 'SRG-APP-000063-DB-000023'
  tag fix_id: 'F-46336r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
