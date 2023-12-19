control 'SV-203593' do
  title 'The operating system must audit all account creations.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account creation. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account creation.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3718r557035_chk'
  tag severity: 'medium'
  tag gid: 'V-203593'
  tag rid: 'SV-203593r557037_rule'
  tag stig_id: 'SRG-OS-000004-GPOS-00004'
  tag gtitle: 'SRG-OS-000004'
  tag fix_id: 'F-3718r557036_fix'
  tag 'documentable'
  tag legacy: ['V-56577', 'SV-70837']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
