control 'SV-213841' do
  title 'SQL Server must have the SQL Server Replication software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The SQL Server Replication software component must be removed from SQL Server if it is unused.'
  desc 'check', 'If the SQL Server Replication feature is used and satisfies organizational requirements, this is not a finding.

In SQL Server Management Studio, Object Explorer, expand  the instance.  Right-click Replication >> New >> Publication.

If the Publication Wizard appears, with no error message, this is a finding.

Right-click Replication >> New >> Subscription.

If the Subscription Wizard appears, with no error message, this is a finding.'
  desc 'fix', 'Either using the Start menu or via the command "control.exe", open the Windows Control Panel.  Open Programs and Features.  Double-click on Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.  Wait for the Remove wizard to appear.

Select the relevant SQL Server instance; click Next.

Select SQL Server Replication; click Next.

Follow the remaining prompts, to remove SQL Server Replication from SQL Server.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15060r312874_chk'
  tag severity: 'medium'
  tag gid: 'V-213841'
  tag rid: 'SV-213841r395853_rule'
  tag stig_id: 'SQL4-00-016826'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-15058r312875_fix'
  tag 'documentable'
  tag legacy: ['SV-82329', 'V-67839']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
