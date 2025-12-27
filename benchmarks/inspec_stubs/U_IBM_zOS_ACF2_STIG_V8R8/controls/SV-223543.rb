control 'SV-223543' do
  title 'IBM z/OS system administrator must develop a process notify appropriate personnel when accounts are created.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of operating system user accounts and notifies administrators and ISSOs that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are created.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are created.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25216r500764_chk'
  tag severity: 'medium'
  tag gid: 'V-223543'
  tag rid: 'SV-223543r533198_rule'
  tag stig_id: 'ACF2-OS-000070'
  tag gtitle: 'SRG-OS-000274-GPOS-00104'
  tag fix_id: 'F-25204r500765_fix'
  tag 'documentable'
  tag legacy: ['SV-106895', 'V-97791']
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
