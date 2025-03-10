control 'SV-214036' do
  title 'SQL Server User Options feature must be disabled, unless specifically required and approved.'
  desc "SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.

The user options option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. The user options option allows you to change the default values of the SET options (if the server's default settings are not appropriate)."
  desc 'check', %q(To determine if "User Options" option is enabled, execute the following query:

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'user options'; 

If the value of "config_value" is "0", this is not a finding. 

If the value of "config_value" is "1", review the system documentation to determine whether the use of "user options" is required and authorized. If it is not authorized, this is a finding.)
  desc 'fix', %q(Disable use of or remove any external application executable object definitions that are not authorized. To disable the use of "User Options" option, from the query prompt: 

sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
sp_configure 'user options', 0;  
GO  
RECONFIGURE;  
GO)
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15253r313891_chk'
  tag severity: 'medium'
  tag gid: 'V-214036'
  tag rid: 'SV-214036r879587_rule'
  tag stig_id: 'SQL6-D0-017100'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-15251r313892_fix'
  tag 'documentable'
  tag legacy: ['SV-94041', 'V-79335']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
