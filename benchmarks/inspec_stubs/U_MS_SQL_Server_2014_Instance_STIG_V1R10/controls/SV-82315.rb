control 'SV-82315' do
  title 'SQL Server must have the SQL Server Reporting Services (SSRS) software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The SQL Server Reporting Services (SSRS) software component must be removed from SQL Server if it is unused.'
  desc 'check', 'If the SQL Server service "SQL Server Reporting Services (<Instance Name>)" is used and satisfies organizational requirements, this is not a finding.

From a command prompt or the Start menu, using an account with System Administrator Privilege, open services.msc.  Look for: "SQL Server Reporting Services (<Instance Name>)".

If the "SQL Server Reporting Services (<Instance Name>)" service exists, this is a finding.'
  desc 'fix', 'Either using the Start menu or via the command "control.exe", open the Windows Control Panel.  Open Programs and Features.  Double-click on Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.  Wait for the Remove wizard to appear.

Select the relevant SQL Server instance; click Next.

Select Reporting Services - Native; select Reporting Services Add-in for SharePoint Products if it is present; click Next.

Follow the remaining prompts, to remove SQL Server Reporting Services from SQL Server.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68393r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67825'
  tag rid: 'SV-82315r1_rule'
  tag stig_id: 'SQL4-00-016600'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-73941r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
