control 'SV-82331' do
  title 'SQL Server must have the Data Quality Client software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The Data Quality Client software component must be removed from SQL Server if it is unused.'
  desc 'check', 'If the Data Quality Client feature is used and satisfies organizational requirements, this is not a finding.

In Windows Server 2008 R2 or lower, click on the Start button.  In the Start menu, navigate to All Programs >> Microsoft SQL Server 2014.

If the "Data Quality Services" folder exists and contains the Data Quality Client program, this is a finding.

In Windows Server 2012 or higher, click on the Start button.  In the Start menu, navigate to Apps >> Microsoft SQL Server 2014.

If the Data Quality Client program is listed, this is a finding.

In Windows Explorer, navigate to <drive where SQL Server is installed>:\\Program Files (x86)\\Microsoft SQL Server\\120\\Tools\\Binn\\DQ\\

If this folder exists and contains the file DataQualityServices.exe, this is a finding.'
  desc 'fix', 'Either using the Start menu or via the command "control.exe", open the Windows Control Panel.  Open Programs and Features.  Double-click on Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.  Wait for the Remove wizard to appear.

Select the relevant SQL Server instance; click Next.

Select Data Quality Client; click Next.

Follow the remaining prompts, to remove Data Quality Client from SQL Server.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67841'
  tag rid: 'SV-82331r1_rule'
  tag stig_id: 'SQL4-00-016830'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-73957r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
