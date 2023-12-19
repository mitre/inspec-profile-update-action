control 'SV-207413' do
  title 'The VMM must automatically audit account modification.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing account modification actions provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM automatically audits account modification.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically audit account modification.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7670r365649_chk'
  tag severity: 'medium'
  tag gid: 'V-207413'
  tag rid: 'SV-207413r379204_rule'
  tag stig_id: 'SRG-OS-000239-VMM-000810'
  tag gtitle: 'SRG-OS-000239'
  tag fix_id: 'F-7670r365650_fix'
  tag 'documentable'
  tag legacy: ['V-57027', 'SV-71287']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
