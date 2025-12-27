control 'SV-80477' do
  title 'Trend Deep Security must maintain a separate execution domain for each executing process.'
  desc 'Applications can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is performed in a manner controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.

An example is a web browser with process isolation that provides tabs that are separate processes using separate address spaces to prevent one tab crashing the entire browser.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure  a separate execution domain for each executing process is maintained.

Review the network topology supporting Deep Security for separation of zones and host OS. 

If the architecture does separate the Deep Security Manager (DSM) from the Database, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to maintain a separate execution domain for each executing process.

Install the Deep Security Manager on a dedicated server within a management zone. Next, connect the DSM to the assigned database provided.  The database should be in separate zone with the necessary firewall rules established for communication between the application server and the DB.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65987'
  tag rid: 'SV-80477r1_rule'
  tag stig_id: 'TMDS-00-000310'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-72063r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
