control 'SV-213958' do
  title 'Access to CLR code must be disabled or restricted, unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.  
 
Applications must adhere to the principles of least functionality by providing only essential capabilities. 
 
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. 
 
The common language runtime (CLR) component of the .NET Framework for Microsoft Windows in SQL Server allows you to write stored procedures, triggers, user-defined types, user-defined functions, user-defined aggregates, and streaming table-valued functions, using any .NET Framework language, including Microsoft Visual Basic .NET and Microsoft Visual C#.  CLR packing assemblies can access resources protected by .NET Code Access Security when it runs managed code.  Specifying UNSAFE enables the code in the assembly complete freedom to perform operations in the SQL Server process space that can potentially compromise the robustness of SQL Server. UNSAFE assemblies can also potentially subvert the security system of either SQL Server or the common language runtime.'
  desc 'check', %q(The common language runtime (CLR) component of the .NET Framework for Microsoft Windows in SQL Server allows you to write stored procedures, triggers, user-defined types, user-defined functions, user-defined aggregates, and streaming table-valued functions, using any .NET Framework language, including Microsoft Visual Basic .NET and Microsoft Visual C#. CLR packing assemblies can access resources protected by .NET Code Access Security when it runs managed code. Specifying UNSAFE enables the code in the assembly complete freedom to perform operations in the SQL Server process space that can potentially compromise the robustness of SQL Server. UNSAFE assemblies can also potentially subvert the security system of either SQL Server or the common language runtime.  

To determine if CLR is enabled, execute the following commands:  

EXEC SP_CONFIGURE 'show advanced options', '1';  
RECONFIGURE WITH OVERRIDE;  
EXEC SP_CONFIGURE 'clr enabled';  

If the value of "config_value" is "0", this is not a finding.  

If the value of "config_value" is "1", review the system documentation to determine whether the use of CLR code is approved. If it is not approved, this is a finding. 

If CLR code is approved, check the database for UNSAFE assembly permission using the following script: 

USE [master]
SELECT *  
FROM sys.assemblies 
WHERE permission_set_desc != 'SAFE' 
AND is_user_defined = 1;

If any records are returned, review the system documentation to determine if the use of UNSAFE assemblies is approved. If it is not approved, this is a finding.)
  desc 'fix', "Disable use of or remove any CLR code that is not authorized. 
 
To disable the use of CLR, from the query prompt:  
 
sp_configure 'show advanced options', 1; 
GO 
RECONFIGURE; 
GO 
sp_configure 'clr enabled', 0; 
GO 
RECONFIGURE; 
GO 
 
For any approved CLR code with Unsafe or External permissions, use the ALTER ASSEMBLY to change the Permission set for the Assembly and ensure a certificate is configured."
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15175r313657_chk'
  tag severity: 'medium'
  tag gid: 'V-213958'
  tag rid: 'SV-213958r879587_rule'
  tag stig_id: 'SQL6-D0-007300'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-15173r313658_fix'
  tag 'documentable'
  tag legacy: ['SV-93885', 'V-79179']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
