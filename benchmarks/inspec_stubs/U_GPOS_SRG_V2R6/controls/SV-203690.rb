control 'SV-203690' do
  title 'The operating system must audit all account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to enable a new or disabled account.  Auditing account modification actions provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account enabling actions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3815r374957_chk'
  tag severity: 'medium'
  tag gid: 'V-203690'
  tag rid: 'SV-203690r851756_rule'
  tag stig_id: 'SRG-OS-000303-GPOS-00120'
  tag gtitle: 'SRG-OS-000303'
  tag fix_id: 'F-3815r374958_fix'
  tag 'documentable'
  tag legacy: ['SV-71481', 'V-57221']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
