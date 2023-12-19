control 'SV-205586' do
  title 'The Mainframe Product must maintain a separate execution domain for each executing process.'
  desc 'Applications can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is performed in a manner controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.

An example is a web browser with process isolation that provides tabs that are separate processes using separate address spaces to prevent one tab crashing the entire browser.'
  desc 'check', 'If the Mainframe Product has no function or capability for multi-session operation, this is not applicable.

If the Mainframe Product is not configured to uniquely define and engineer each session to execute independently of any other session, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to uniquely define and engineer each session to execute independently of any other session.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5852r299985_chk'
  tag severity: 'medium'
  tag gid: 'V-205586'
  tag rid: 'SV-205586r851350_rule'
  tag stig_id: 'SRG-APP-000431-MFP-000312'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-5852r299986_fix'
  tag 'documentable'
  tag legacy: ['SV-82961', 'V-68471']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
