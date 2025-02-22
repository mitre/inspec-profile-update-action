control 'SV-213840' do
  title 'SQL Server must have the Master Data Services software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The Master Data Services software component must be removed from SQL Server if it is unused.'
  desc 'check', 'If the Master Data Services feature is used and satisfies organizational requirements, this is not a finding.

Click on the Start button.  Navigate to >> Microsoft SQL Server 2014 >> Master Data Services.

If the "Master Data Services" folder exists and contains any programs, this is a finding.

In Windows Explorer, navigate to <drive where SQL Server is installed>:\\Program Files\\Microsoft SQL Server\\120\\Master Data Services\\.

If this exists and contains any files, this is a finding.'
  desc 'fix', %q(Either using the Start menu or via the command "control.exe", open the Windows Control Panel.  Open Programs and Features.  Double-click on Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.  Wait for the Remove wizard to appear.

Select '<< Remove shared features only >>'; click Next.  Note: all SQL Server 2014 instances will be affected by this action.)

Select Master Data Services; click Next.

Follow the remaining prompts, to remove Master Data Services from SQL Server.)
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15059r312871_chk'
  tag severity: 'medium'
  tag gid: 'V-213840'
  tag rid: 'SV-213840r395853_rule'
  tag stig_id: 'SQL4-00-016820'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-15057r312872_fix'
  tag 'documentable'
  tag legacy: ['SV-82327', 'V-67837']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
