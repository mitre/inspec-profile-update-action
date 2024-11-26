control 'SV-82343' do
  title 'The SQL Server default account [sa] must be disabled.'
  desc "SQL Server's [sa] account has special privileges required to administer the database. The [sa] account is a well-known SQL Server account and is likely to be targeted by attackers and thus more prone to providing unauthorized access to the database.

This [sa] default account is administrative and could lead to catastrophic consequences, including the complete loss of control over SQL Server.

If the [sa] default account is not disabled, an attacker might be able to gain access through the account. SQL Server by default, at installation, disables the [sa] account.

Some applications that run on SQL Server require the [sa] account to be enabled in order for the application to function properly. These applications that require the [sa] account to be enabled are usually legacy systems."
  desc 'check', 'Check SQL Server settings to determine if the [sa] (system administrator) account has been disabled by executing the following query:

USE master;
GO
SELECT name, is_disabled
FROM sys.sql_logins
WHERE principal_id = 1;
GO

Verify that the "name" column contains the current name of the [sa] database server account (see note).

If the "is_disabled" column is not set to 1, this is a finding.

Note: If the [sa] account name has been changed per SQL4-00-010200, its new name should appear in the query results.'
  desc 'fix', %q(Modify the enabled flag of SQL Server's [sa] (system administrator) account by running the following script. If the account name has been changed per SQL4-00-010200, replace the letters "sa" in the query with the new name.

USE master;
GO
ALTER LOGIN [sa] DISABLE;
GO)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68421r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67853'
  tag rid: 'SV-82343r1_rule'
  tag stig_id: 'SQL4-00-017100'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-73969r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
