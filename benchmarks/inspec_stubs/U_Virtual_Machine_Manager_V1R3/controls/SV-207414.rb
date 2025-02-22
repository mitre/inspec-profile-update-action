control 'SV-207414' do
  title 'The VMM must automatically audit account disabling actions.'
  desc 'When VMM accounts are disabled, user accessibility is affected. Once an attacker establishes access to a system, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account disabling actions provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM automatically audits account disabling actions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically audit account disabling actions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7671r365652_chk'
  tag severity: 'medium'
  tag gid: 'V-207414'
  tag rid: 'SV-207414r379207_rule'
  tag stig_id: 'SRG-OS-000240-VMM-000820'
  tag gtitle: 'SRG-OS-000240'
  tag fix_id: 'F-7671r365653_fix'
  tag 'documentable'
  tag legacy: ['V-57029', 'SV-71289']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
