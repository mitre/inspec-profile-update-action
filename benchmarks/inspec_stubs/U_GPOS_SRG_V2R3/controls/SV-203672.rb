control 'SV-203672' do
  title 'The operating system must protect audit tools from unauthorized access.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the operating system protects audit tools from unauthorized access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3797r374903_chk'
  tag severity: 'medium'
  tag gid: 'V-203672'
  tag rid: 'SV-203672r379237_rule'
  tag stig_id: 'SRG-OS-000256-GPOS-00097'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-3797r374904_fix'
  tag 'documentable'
  tag legacy: ['V-57173', 'SV-71433']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
