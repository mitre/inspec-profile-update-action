control 'SV-213836' do
  title 'SQL Server must have the SQL Server Analysis Services (SSAS) software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The SQL Server Analysis Service (SSAS) software component removed from SQL Server if it is unused.'
  desc 'check', 'If the SQL Server service "SQL Server Analysis Services (<Instance Name>)" is used and satisfies organizational requirements, this is not a finding.

From a command prompt or the Start menu, using an account with System Administrator Privilege, open services.msc.  Look for: "SQL Server Analysis Services (<Instance Name>)".

If the "SQL Server Analysis Services (<Instance Name>)" service exists, this is a finding.'
  desc 'fix', 'Either using the Start menu or via the command "control.exe", open the Windows Control Panel.  Open Programs and Features.  Double-click on Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.  Wait for the Remove wizard to appear.

Select the relevant SQL Server instance; click Next.

Select Analysis Services; click Next.

Follow the remaining prompts, to remove SQL Server Analysis Services from SQL Server.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15055r312859_chk'
  tag severity: 'medium'
  tag gid: 'V-213836'
  tag rid: 'SV-213836r395853_rule'
  tag stig_id: 'SQL4-00-016800'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-15053r312860_fix'
  tag 'documentable'
  tag legacy: ['SV-82319', 'V-67829']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
