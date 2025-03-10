control 'SV-203679' do
  title 'The operating system must notify system administrators and ISSOs when accounts are modified.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the modification of operating system user accounts and notifies the system administrator and ISSO of changes. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system notifies System Administrators and Information System Security Officers when accounts are modified. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to notify System Administrators and Information System Security Officers when accounts are modified.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3804r374924_chk'
  tag severity: 'medium'
  tag gid: 'V-203679'
  tag rid: 'SV-203679r379324_rule'
  tag stig_id: 'SRG-OS-000275-GPOS-00105'
  tag gtitle: 'SRG-OS-000275'
  tag fix_id: 'F-3804r374925_fix'
  tag 'documentable'
  tag legacy: ['SV-71457', 'V-57197']
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
