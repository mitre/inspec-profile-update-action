control 'SV-53293' do
  title 'SQL Server must have the SQL Server Integrated Services (SSIS) software component removed from SQL Server if SSIS is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software demonstrations or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, yet cannot be disabled.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Unused and unnecessary SQL Server components increase the number of available attack vectors to SQL Server by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

SQL Server must have the SQL Server Integrated Services (SSIS) software component removed from SQL Server if SSIS is unused.'
  desc 'check', 'If the SQL Server service "SQL Server Integration Services 11.0" is used and the service satisfies functional organizational requirement, this is not a finding.

If there is no functional organizational requirement for the "SQL Server Integration Services 11.0" service make sure that the service is not installed or is disabled.

From command prompt, using an account with System Administrator Privilege, open dcomcnfg. Navigate to Console Root >> Services (Local) >> [sort by name] >> locate: "SQL Server Integration Services 11.0".

If the "SQL Server Integration Services 11.0" service does not exist, this is not a finding.

If the "SQL Server Integration Services 11.0" status is "Started" or the "Startup Type" is not "Disabled", this is a finding.'
  desc 'fix', 'Remove the SQL Server Integrated Services (SSIS) software component.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47594r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40939'
  tag rid: 'SV-53293r2_rule'
  tag stig_id: 'SQL2-00-016700'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-46221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
