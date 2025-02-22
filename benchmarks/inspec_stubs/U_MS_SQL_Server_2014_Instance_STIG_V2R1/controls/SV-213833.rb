control 'SV-213833' do
  title 'SQL Server must have the SQL Server Data Tools (SSDT) software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The SQL Server Data Tools (SSDT) software component must be removed from SQL Server if it is unused.'
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
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15052r312850_chk'
  tag severity: 'medium'
  tag gid: 'V-213833'
  tag rid: 'SV-213833r395853_rule'
  tag stig_id: 'SQL4-00-016500'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-15050r312851_fix'
  tag 'documentable'
  tag legacy: ['SV-82313', 'V-67823']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
