control 'SV-214028' do
  title 'The SQL Server default account [sa] must be disabled.'
  desc "SQL Server's [sa] account has special privileges required to administer the database. The [sa] account is a well-known SQL Server account and is likely to be targeted by attackers and thus more prone to providing unauthorized access to the database. 

This [sa] default account is administrative and could lead to catastrophic consequences, including the complete loss of control over SQL Server. If the [sa] default account is not disabled, an attacker might be able to gain access through the account. SQL Server by default, at installation, disables the [sa] account. 

Some applications that run on SQL Server require the [sa] account to be enabled in order for the application to function properly. These applications that require the [sa] account to be enabled are usually legacy systems."
  desc 'check', 'Check SQL Server settings to determine if the [sa] (system administrator) account has been disabled by executing the following query:

USE master;
GO
SELECT name, is_disabled
FROM sys.sql_logins
WHERE principal_id = 1;
GO

Verify that the "name" column contains the current name of the [sa] database server account.

If the "is_disabled" column is not set to “1”, this is a finding.'
  desc 'fix', "Modify the enabled flag of SQL Server's [sa] (system administrator) account by running the following script.
USE master; 
GO 
ALTER LOGIN [sa] DISABLE; 
GO"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15245r313867_chk'
  tag severity: 'medium'
  tag gid: 'V-214028'
  tag rid: 'SV-214028r617437_rule'
  tag stig_id: 'SQL6-D0-016200'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-15243r313868_fix'
  tag 'documentable'
  tag legacy: ['SV-94023', 'V-79317']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
