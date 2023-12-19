control 'SV-207427' do
  title 'The VMM must notify system administrators and ISSOs when accounts are created.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of VMM user accounts and notifies the system administrator and ISSO that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM notifies system administrators and ISSOs when accounts are created.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to notify system administrators and ISSOs when accounts are created.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7684r365691_chk'
  tag severity: 'medium'
  tag gid: 'V-207427'
  tag rid: 'SV-207427r379321_rule'
  tag stig_id: 'SRG-OS-000274-VMM-000960'
  tag gtitle: 'SRG-OS-000274'
  tag fix_id: 'F-7684r365692_fix'
  tag 'documentable'
  tag legacy: ['SV-71315', 'V-57055']
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
