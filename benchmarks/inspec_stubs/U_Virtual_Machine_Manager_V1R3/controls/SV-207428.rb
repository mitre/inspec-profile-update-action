control 'SV-207428' do
  title 'The VMM must notify the system administrator and ISSO when accounts are modified.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of VMM user accounts and notifies the system administrator and ISSO that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM notifies the system administrator and ISSO when accounts are modified.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to notify the system administrator and ISSO when accounts are modified.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7685r365694_chk'
  tag severity: 'medium'
  tag gid: 'V-207428'
  tag rid: 'SV-207428r379324_rule'
  tag stig_id: 'SRG-OS-000275-VMM-000970'
  tag gtitle: 'SRG-OS-000275'
  tag fix_id: 'F-7685r365695_fix'
  tag 'documentable'
  tag legacy: ['V-57057', 'SV-71317']
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
