control 'SV-213838' do
  title 'SQL Server must have the SQL Server Distributed Replay Controller software component removed if it is unused.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default or selected for installation by an administrator, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Applications must adhere to the principles of least functionality by providing only essential capabilities.  Unused and unnecessary SQL Server components increase the number of available attack vectors.  By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

The SQL Server Distributed Replay Controller software component must be removed if it is unused.'
  desc 'check', 'If the SQL Server service "SQL Server Distributed Replay Controller" is used and satisfies organizational requirements, this is not a finding.

From a command prompt or the Start menu, using an account with System Administrator Privilege, open services.msc.  Look for: "SQL Server Distributed Replay Controller".

If the "SQL Server Distributed Replay Controller" service exists, this is a finding.'
  desc 'fix', %q(Either using the Start menu or via the command "control.exe", open the Windows Control Panel.  Open Programs and Features.  Double-click on Microsoft SQL Server 2014.  In the dialog box that appears, select Remove.  Wait for the Remove wizard to appear.

Select '<< Remove shared features only >>'; click Next.  (Note: all instances of SQL Server 2012 or higher may be affected by this action.)

Select Distributed Replay Controller; click Next.

Follow the remaining prompts, to remove Distributed Replay Controller from SQL Server.)
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15057r312865_chk'
  tag severity: 'medium'
  tag gid: 'V-213838'
  tag rid: 'SV-213838r395853_rule'
  tag stig_id: 'SQL4-00-016810'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-15055r312866_fix'
  tag 'documentable'
  tag legacy: ['SV-82323', 'V-67833']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
