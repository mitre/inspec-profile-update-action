control 'SV-213809' do
  title 'SQL Server default account [sa] must have its name changed.'
  desc "SQL Server's [sa] account has special privileges required to administer the database. The [sa] account is a well-known SQL Server account name and is likely to be targeted by attackers, and is thus more prone to providing unauthorized access to the database.

Since the SQL Server [sa] is administrative in nature, the compromise of a default account can have catastrophic consequences, including the complete loss of control over SQL Server. Since SQL Server needs for this account to exist and it should not be removed, one way to mitigate this risk is to change the [sa] account name."
  desc 'check', %q(Verify the SQL Server default [sa] (system administrator) account name has been changed by executing the following query:

USE master;
GO
SELECT *
FROM sys.sql_logins
WHERE [name] = 'sa' OR [principal_id] = 1;
GO

If the login account name "SA" or "sa" appears in the query output, this is a finding.)
  desc 'fix', "Modify the SQL Server's [sa] (system administrator) account by running the following script:

USE master;
GO
ALTER LOGIN [sa] WITH NAME = <new name>;
GO"
  impact 0.3
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15028r312778_chk'
  tag severity: 'low'
  tag gid: 'V-213809'
  tag rid: 'SV-213809r395853_rule'
  tag stig_id: 'SQL4-00-010200'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-15026r312779_fix'
  tag 'documentable'
  tag legacy: ['SV-82345', 'V-67855']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
