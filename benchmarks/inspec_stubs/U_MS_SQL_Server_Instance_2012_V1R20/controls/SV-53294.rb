control 'SV-53294' do
  title 'SQL Server must have the SQL Server Reporting Service (SSRS) software component removed from SQL Server if SSRS is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software demonstrations or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, yet cannot be disabled.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Unused and unnecessary SQL Server components increase the number of available attack vectors to SQL Server by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

SQL Server must have the SQL Server Reporting Service (SSRS) software component removed from SQL Server if SSRS is unused.'
  desc 'check', 'If there is no functional organizational requirement for the "SQL Server Reporting Services (MSSQLSERVER)" service, make sure that the service is not installed or that the service is disabled.

If the SQL Server service "SQL Server Reporting Services (MSSQLSERVER)" is used and the service satisfies functional organizational requirement, this is not a finding.


From command prompt, using an account with System Administrator Privilege, open dcomcnfg. Navigate to Console Root >> Services (Local) >> [sort by name] >> locate: "SQL Server Reporting Services (MSSQLSERVER)".

If the "SQL Server Reporting Services (MSSQLSERVER)" service does not exist, this is not a finding.

If the "SQL Server Reporting Services (MSSQLSERVER)" status is "Started" or the "Startup Type" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Remove the SSRS from SQL Server.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47595r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40940'
  tag rid: 'SV-53294r2_rule'
  tag stig_id: 'SQL2-00-016600'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-46222r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
