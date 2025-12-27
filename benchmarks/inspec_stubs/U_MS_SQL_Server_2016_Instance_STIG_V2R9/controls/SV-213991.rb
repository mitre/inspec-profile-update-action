control 'SV-213991' do
  title 'SQL Server must maintain a separate execution domain for each executing process.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space.  
 
Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process.  
 
Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', %q(Review the server documentation to determine whether use of CLR assemblies is required. Run the following query to determine whether CLR is enabled for the instance: 
 
SELECT name, value, value_in_use 
FROM sys.configurations 
WHERE name = 'clr enabled' 
 
If "value_in_use" is a "1" and CLR is not required, this is a finding.)
  desc 'fix', "Disable CLR support in SQL Server by executing the following query: 
 
EXEC sp_configure 'clr enabled', 0 
GO 
 
RECONFIGURE 
GO"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15208r313756_chk'
  tag severity: 'medium'
  tag gid: 'V-213991'
  tag rid: 'SV-213991r879802_rule'
  tag stig_id: 'SQL6-D0-012300'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-15206r313757_fix'
  tag 'documentable'
  tag legacy: ['SV-93949', 'V-79243']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
