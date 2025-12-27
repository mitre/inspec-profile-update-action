control 'SV-203673' do
  title 'The operating system must protect audit tools from unauthorized modification.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the operating system protects audit tools from unauthorized modification. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit tools from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3798r374906_chk'
  tag severity: 'medium'
  tag gid: 'V-203673'
  tag rid: 'SV-203673r379240_rule'
  tag stig_id: 'SRG-OS-000257-GPOS-00098'
  tag gtitle: 'SRG-OS-000257'
  tag fix_id: 'F-3798r374907_fix'
  tag 'documentable'
  tag legacy: ['SV-71435', 'V-57175']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
