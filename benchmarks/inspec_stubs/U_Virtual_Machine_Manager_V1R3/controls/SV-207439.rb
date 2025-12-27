control 'SV-207439' do
  title 'The VMM must automatically audit account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM automatically audits account enabling actions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7696r365727_chk'
  tag severity: 'medium'
  tag gid: 'V-207439'
  tag rid: 'SV-207439r854612_rule'
  tag stig_id: 'SRG-OS-000303-VMM-001090'
  tag gtitle: 'SRG-OS-000303'
  tag fix_id: 'F-7696r365728_fix'
  tag 'documentable'
  tag legacy: ['V-57079', 'SV-71339']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
