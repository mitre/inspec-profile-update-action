control 'SV-214041' do
  title 'SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved.'
  desc 'SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.

The External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed.'
  desc 'check', %q(To determine if "External Scripts Enabled" option is enabled, execute the following query: 

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'external scripts enabled'; 

If the value of "config_value" is "0", this is not a finding. 

If the value of "config_value" is "1", review the system documentation to determine whether the use of "External Scripts Enabled" is required and authorized. If it is not authorized, this is a finding.)
  desc 'fix', %q(Disable use of or remove any external application executable object definitions that are not authorized. To disable the use of "External Scripts Enabled" option, from the query prompt: 

sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
sp_configure 'external scripts enabled', 0;  
GO  
RECONFIGURE;  
GO)
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15258r313906_chk'
  tag severity: 'medium'
  tag gid: 'V-214041'
  tag rid: 'SV-214041r879587_rule'
  tag stig_id: 'SQL6-D0-017700'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-15256r313907_fix'
  tag 'documentable'
  tag legacy: ['SV-94053', 'V-79347']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
