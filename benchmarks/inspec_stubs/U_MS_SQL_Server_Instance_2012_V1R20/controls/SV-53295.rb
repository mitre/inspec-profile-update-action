control 'SV-53295' do
  title 'SQL Server must have the SQL Server Data Tools (SSDT) software component removed from SQL Server if SSDT is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, yet cannot be disabled. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Unused and unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.


SQL Server must have the SQL Server Data Tools (SSDT) software component removed from SQL Server if SSDT is unused.'
  desc 'check', "Review the list of components and features installed with the database. Using an account with System Administrator privileges, from Command Prompt, open control.exe.

Navigate to Programs and Features. Check for the following entries in the 'Uninstall or change a program' window.

Microsoft SQL Server Data Tools - Database Projects - Web installer entry point
Prerequisites for SSDT

If SQL Server Data Tools is not documented as a server requirement, and these entries exist, this is a finding."
  desc 'fix', "Document the requirement for SQL Server Data Tools to reside on this server.

If it is not required, using an account with System Administrator privileges, from Command Prompt, open control.exe.

Navigate to Programs and Features. Remove the following entries in the 'Uninstall or change a program' window.

Microsoft SQL Server Data Tools - Database Projects - Web installer entry point
Prerequisites for SSDT"
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47596r2_chk'
  tag severity: 'high'
  tag gid: 'V-40941'
  tag rid: 'SV-53295r2_rule'
  tag stig_id: 'SQL2-00-016500'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-46223r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
