control 'SV-203667' do
  title 'The operating system must audit all account disabling actions.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account disabling actions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account disabling actions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3792r374828_chk'
  tag severity: 'medium'
  tag gid: 'V-203667'
  tag rid: 'SV-203667r379207_rule'
  tag stig_id: 'SRG-OS-000240-GPOS-00090'
  tag gtitle: 'SRG-OS-000240'
  tag fix_id: 'F-3792r374829_fix'
  tag 'documentable'
  tag legacy: ['V-56917', 'SV-71177']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
