control 'SV-53289' do
  title 'Access to xp_cmdshell must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plug-ins not related to requirements; or providing a wide array of functionality not required for every mission, but which cannot be disabled. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

DBMSs may spawn additional external processes to execute procedures that are defined in the DBMS, but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.

The xp_cmdshell extended stored procedure allows execution of host executables outside the controls of database access permissions. This access may be exploited by malicious users who have compromised the integrity of the SQL Server database process to control the host operating system to perpetrate additional malicious activity.'
  desc 'check', "To determine if xp_cmdshell is enabled, execute the following commands:

EXEC SP_CONFIGURE 'show advanced option', '1';
RECONFIGURE WITH OVERRIDE;
EXEC SP_CONFIGURE 'xp_cmdshell';

If the value of config_value is 1, this is a finding."
  desc 'fix', "To disable the use of xp_cmdshell, from the query prompt:
EXEC sp_configure 'show advanced options', 1
GO

RECONFIGURE
GO

EXEC sp_configure 'xp_cmdshell', 0
GO

RECONFIGURE
GO"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47590r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40935'
  tag rid: 'SV-53289r2_rule'
  tag stig_id: 'SQL2-00-017200'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-46217r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
