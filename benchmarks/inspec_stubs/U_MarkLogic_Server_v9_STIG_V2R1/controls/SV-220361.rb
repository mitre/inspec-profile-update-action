control 'SV-220361' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

DBMSs may spawn additional external processes to execute procedures that are defined in the DBMS but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.'
  desc 'check', 'Verify whether external executables are being used. If so, check with the ISSO to determine if the use of the external executables (MLSQL/odbc client and Converters) is authorized.

If it is not, this is a finding.

To check for Converters, issue the following command at a command prompt with a user that has administrative privileges.
> sudo yum info MarkLogicConverters

If the command returns information on the version of MarkLogic converters installed, and use of this package has not been authorized, this is a finding.

To check for MLSQL/odbc client, issue the following command at a command prompt with a user that has administrative privileges.
> sudo yum info mlsqlodbc

If the command returns information on the version of MLSQL odbc client install, and use of this package has not been authorized, this is a finding.'
  desc 'fix', 'If the use of the included external executables (MLSQL/odbc and/or CONVERT) is not authorized by the ISSO then remove the executables from the MarkLogic installation directory, find the executables by name for the different operating systems.

To remove Converters, issue the following command at a command prompt with a user that has administrative privileges.
> sudo yum remove MarkLogicConverters

To remove MLSQL/odbc client, issue the following command at a command prompt with a user that has administrative privileges.
> sudo yum info mlsqlodbc'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22076r401534_chk'
  tag severity: 'medium'
  tag gid: 'V-220361'
  tag rid: 'SV-220361r622777_rule'
  tag stig_id: 'ML09-00-003300'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-22065r401535_fix'
  tag 'documentable'
  tag legacy: ['SV-110069', 'V-100965']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
