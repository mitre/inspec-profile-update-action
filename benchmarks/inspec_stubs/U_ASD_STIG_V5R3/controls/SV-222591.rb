control 'SV-222591' do
  title 'The application must maintain a separate execution domain for each executing process.'
  desc 'Applications can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is performed in a manner controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.

An example is a web browser with process isolation that provides tabs that are separate processes using separate address spaces to prevent one tab crashing the entire browser.'
  desc 'check', 'Review the application documentation, the architecture documentation and interview the application administrator.

Identify if the application architecture provides the capability to sandbox executing processes so as to prevent a process in one application domain from sharing another application domain.

Ask the application administrator to demonstrate how the application processes are separated. This may be demonstrated by examining the OS processes running on the system and identifying the separate application processes.

If the application does not maintain a separate execution domain for each executing process, this is a finding.'
  desc 'fix', 'Design and configure applications to maintain a separate execution domain for each executing process.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24261r493681_chk'
  tag severity: 'medium'
  tag gid: 'V-222591'
  tag rid: 'SV-222591r879802_rule'
  tag stig_id: 'APSC-DV-002370'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-24250r493682_fix'
  tag 'documentable'
  tag legacy: ['SV-84855', 'V-70233']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
