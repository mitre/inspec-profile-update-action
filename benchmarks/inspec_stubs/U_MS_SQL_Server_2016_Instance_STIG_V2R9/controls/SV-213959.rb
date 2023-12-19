control 'SV-213959' do
  title 'Access to Non-Standard extended stored procedures must be disabled or restricted, unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.  
 
Applications must adhere to the principles of least functionality by providing only essential capabilities. 
 
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. 
 
Extended stored procedures are DLLs that an instance of SQL Server can dynamically load and run. Extended stored procedures run directly in the address space of an instance of SQL Server and are programmed by using the SQL Server Extended Stored Procedure API.  Non-Standard extended stored procedures can compromise the integrity of the SQL Server process.  This feature will be removed in a future version of Microsoft SQL Server. Do not use this feature in new development work, and modify applications that currently use this feature as soon as possible.'
  desc 'check', 'Extended stored procedures are DLLs that an instance of SQL Server can dynamically load and run. Extended stored procedures run directly in the address space of an instance of SQL Server and are programmed by using the SQL Server Extended Stored Procedure API.   
 
Non-Standard extended stored procedures can compromise the integrity of the SQL Server process.  This feature will be removed in a future version of Microsoft SQL Server. Do not use this feature in new development work, and modify applications that currently use this feature as soon as possible.  
 
To determine if non-standard extended stored procedures exist, run the following:

------------------------------------------------------------------------
USE [master]
GO
DECLARE @xplist AS TABLE
(
       xp_name sysname,
       source_dll nvarchar(255)
)
INSERT INTO @xplist
EXEC sp_helpextendedproc

SELECT X.xp_name, X.source_dll, O.is_ms_shipped FROM @xplist X JOIN sys.all_objects O ON X.xp_name = O.name WHERE O.is_ms_shipped = 0 ORDER BY X.xp_name
------------------------------------------------------------------------
 
If any records are returned, review the system documentation to determine whether the use of Non-Standard extended stored procedures are required and approved.

If it is not approved, this is a finding.'
  desc 'fix', "Remove any Non-Standard extended stored procedures that are not documented and approved. 
 
sp_dropextendedproc 'proc name'"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15176r313660_chk'
  tag severity: 'medium'
  tag gid: 'V-213959'
  tag rid: 'SV-213959r879587_rule'
  tag stig_id: 'SQL6-D0-007400'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-15174r313661_fix'
  tag 'documentable'
  tag legacy: ['SV-93887', 'V-79181']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
