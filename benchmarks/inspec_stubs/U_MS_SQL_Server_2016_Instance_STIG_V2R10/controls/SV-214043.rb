control 'SV-214043' do
  title 'SQL Server Replication Xps feature must be disabled, unless specifically required and approved.'
  desc 'SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.

Enabling the replication XPs opens a significant attack surface area that can be used by an attacker to gather information about the system and potentially abuse the privileges of SQL Server.'
  desc 'check', %q(To determine if the "Replication Xps" option is enabled, execute the following query: 

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'replication xps'; 

If the value of "config_value" is "0", this is not a finding. 

If the value of "config_value" is "1", review the system documentation to determine whether the use of "Replication Xps" is required and authorized. If it is not authorized, this is a finding.)
  desc 'fix', %q(Disable use of or remove any external application executable object definitions that are not authorized. To disable the use of "Replication Xps" option, from the query prompt: 

sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
sp_configure 'replication xps', 0;  
GO  
RECONFIGURE;  
GO)
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15260r313912_chk'
  tag severity: 'medium'
  tag gid: 'V-214043'
  tag rid: 'SV-214043r879587_rule'
  tag stig_id: 'SQL6-D0-017900'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-15258r313913_fix'
  tag 'documentable'
  tag legacy: ['SV-94057', 'V-79351']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
