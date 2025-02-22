control 'SV-213992' do
  title 'SQL Server services must be configured to run under unique dedicated user accounts.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', 'Review the server documentation to obtain a listing of required service accounts. Review the accounts configured for all SQL Server services installed on the server. 
 
Click Start >> Type "SQL Server Configuration Manager" >> Launch the program >> Click SQL Server Services tree node. Review the "Log On As" column for each service. 
 
If any services are configured with the same service account or are configured with an account that is not documented and authorized, this is a finding.'
  desc 'fix', 'Configure SQL Server services to have a documented, dedicated account.  
 
For non-domain servers, consider using virtual service accounts (VSA). See https://msdn.microsoft.com/en-us/library/ms143504.aspx#VA_Desc for more information. 
 
For standalone, domain-joined servers, consider using managed service accounts. See https://msdn.microsoft.com/en-us/library/ms143504.aspx#MSA for more information. 
 
For clustered instances, consider using group managed service accounts. See https://msdn.microsoft.com/en-us/library/ms143504.aspx#GMSA or https://blogs.msdn.microsoft.com/markweberblog/2016/05/25/group-managed-service-accounts-gmsa-and-sql-server-2016/ for more information.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15209r313759_chk'
  tag severity: 'medium'
  tag gid: 'V-213992'
  tag rid: 'SV-213992r879802_rule'
  tag stig_id: 'SQL6-D0-012400'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-15207r313760_fix'
  tag 'documentable'
  tag legacy: ['SV-93951', 'V-79245']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
