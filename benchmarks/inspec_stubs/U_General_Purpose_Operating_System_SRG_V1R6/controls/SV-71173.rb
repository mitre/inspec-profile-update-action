control 'SV-71173' do
  title 'The operating system must audit all account modifications.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to modify an existing account.  Auditing account modification actions provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account modification. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account modification.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57483r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56913'
  tag rid: 'SV-71173r2_rule'
  tag stig_id: 'SRG-OS-000239-GPOS-00089'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag fix_id: 'F-61809r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
