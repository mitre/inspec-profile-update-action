control 'SV-224014' do
  title 'The IBM z/OS System Administrator must develop a process to notify appropriate personnel when accounts are modified.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of operating system user accounts and notifies administrators and ISSOs that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are modified.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are modified.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25687r516441_chk'
  tag severity: 'medium'
  tag gid: 'V-224014'
  tag rid: 'SV-224014r561402_rule'
  tag stig_id: 'TSS0-OS-000180'
  tag gtitle: 'SRG-OS-000275-GPOS-00105'
  tag fix_id: 'F-25675r516442_fix'
  tag 'documentable'
  tag legacy: ['V-98737', 'SV-107841']
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
