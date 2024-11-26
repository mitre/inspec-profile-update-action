control 'SV-207415' do
  title 'The VMM must automatically audit account removal actions.'
  desc 'When VMM accounts are removed, user accessibility is affected. Once an attacker establishes access to a system, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM automatically audits account removal actions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically audit account removal actions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7672r365655_chk'
  tag severity: 'medium'
  tag gid: 'V-207415'
  tag rid: 'SV-207415r379210_rule'
  tag stig_id: 'SRG-OS-000241-VMM-000830'
  tag gtitle: 'SRG-OS-000241'
  tag fix_id: 'F-7672r365656_fix'
  tag 'documentable'
  tag legacy: ['V-57031', 'SV-71291']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
