control 'SV-70837' do
  title 'The operating system must audit all account creations.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account creation. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account creation.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56577'
  tag rid: 'SV-70837r2_rule'
  tag stig_id: 'SRG-OS-000004-GPOS-00004'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-61473r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
