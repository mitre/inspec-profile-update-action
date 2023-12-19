control 'SV-224013' do
  title 'The IBM z/OS System Administrator must develop a process to notify appropriate personnel when accounts are created.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of operating system user accounts and notifies administrators and ISSOs that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are created.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are created.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25686r516438_chk'
  tag severity: 'medium'
  tag gid: 'V-224013'
  tag rid: 'SV-224013r561402_rule'
  tag stig_id: 'TSS0-OS-000170'
  tag gtitle: 'SRG-OS-000274-GPOS-00104'
  tag fix_id: 'F-25674r516439_fix'
  tag 'documentable'
  tag legacy: ['V-98735', 'SV-107839']
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
