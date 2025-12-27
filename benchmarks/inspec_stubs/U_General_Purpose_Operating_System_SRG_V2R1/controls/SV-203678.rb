control 'SV-203678' do
  title 'The operating system must notify system administrators and ISSOs when accounts are created.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to create a new account.  Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of operating system user accounts and notifies administrators and ISSOs that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system notifies System Administrators and Information System Security Officers when accounts are created. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to notify System Administrators and Information System Security Officers when accounts are created.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3803r374921_chk'
  tag severity: 'medium'
  tag gid: 'V-203678'
  tag rid: 'SV-203678r379321_rule'
  tag stig_id: 'SRG-OS-000274-GPOS-00104'
  tag gtitle: 'SRG-OS-000274'
  tag fix_id: 'F-3803r374922_fix'
  tag 'documentable'
  tag legacy: ['V-57195', 'SV-71455']
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
