control 'SV-206606' do
  title 'The DBMS must maintain a separate execution domain for each executing process.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', 'Review the DBMS architecture to find out if and how it protects the private resources of one process (such as working memory, temporary tables, uncommitted data and, especially, executable code) from unauthorized access or modification by another user or process.

If it is not capable of maintaining a separate execution domain for each executing process, this is a finding.

If the DBMS is capable of maintaining a separate execution domain for each executing process, but is configured not to do so, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of maintaining a separate execution domain for each executing process.

If this is a configurable feature, configure the DBMS to implement it.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6866r291486_chk'
  tag severity: 'medium'
  tag gid: 'V-206606'
  tag rid: 'SV-206606r617447_rule'
  tag stig_id: 'SRG-APP-000431-DB-000388'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-6866r291487_fix'
  tag 'documentable'
  tag legacy: ['SV-72603', 'V-58173']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
