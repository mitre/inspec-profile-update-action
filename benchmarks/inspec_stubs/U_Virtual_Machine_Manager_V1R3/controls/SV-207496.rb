control 'SV-207496' do
  title 'The VMM must maintain a separate execution domain for each executing process.'
  desc 'VMMs can maintain separate execution domains for each executing process by assigning each process a separate address space. Each VMM process has a distinct address space so that communication between processes is performed in a manner controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces. This capability is available in most commercial VMMs that employ multistate processor technologies.'
  desc 'check', 'Verify the VMM maintains a separate execution domain for each executing process.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to maintain a separate execution domain for each executing process.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7753r365892_chk'
  tag severity: 'medium'
  tag gid: 'V-207496'
  tag rid: 'SV-207496r854670_rule'
  tag stig_id: 'SRG-OS-000408-VMM-001670'
  tag gtitle: 'SRG-OS-000408'
  tag fix_id: 'F-7753r365893_fix'
  tag 'documentable'
  tag legacy: ['SV-71553', 'V-57293']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
