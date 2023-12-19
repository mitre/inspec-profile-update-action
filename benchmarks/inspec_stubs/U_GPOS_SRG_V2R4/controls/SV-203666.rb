control 'SV-203666' do
  title 'The operating system must audit all account modifications.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to modify an existing account.  Auditing account modification actions provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account modification. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account modification.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3791r374825_chk'
  tag severity: 'medium'
  tag gid: 'V-203666'
  tag rid: 'SV-203666r379204_rule'
  tag stig_id: 'SRG-OS-000239-GPOS-00089'
  tag gtitle: 'SRG-OS-000239'
  tag fix_id: 'F-3791r374826_fix'
  tag 'documentable'
  tag legacy: ['V-56913', 'SV-71173']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
