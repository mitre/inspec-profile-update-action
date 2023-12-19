control 'SV-203674' do
  title 'The operating system must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the operating system protects audit tools from unauthorized deletion. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit tools from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3799r374909_chk'
  tag severity: 'medium'
  tag gid: 'V-203674'
  tag rid: 'SV-203674r379243_rule'
  tag stig_id: 'SRG-OS-000258-GPOS-00099'
  tag gtitle: 'SRG-OS-000258'
  tag fix_id: 'F-3799r374910_fix'
  tag 'documentable'
  tag legacy: ['V-57177', 'SV-71437']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
