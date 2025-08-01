control 'SV-203668' do
  title 'The operating system must audit all account removal actions.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must audit account removal actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account removal actions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account removal actions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3793r374831_chk'
  tag severity: 'medium'
  tag gid: 'V-203668'
  tag rid: 'SV-203668r379210_rule'
  tag stig_id: 'SRG-OS-000241-GPOS-00091'
  tag gtitle: 'SRG-OS-000241'
  tag fix_id: 'F-3793r374832_fix'
  tag 'documentable'
  tag legacy: ['V-56921', 'SV-71181']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
