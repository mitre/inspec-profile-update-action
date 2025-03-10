control 'SV-223541' do
  title 'IBM z/OS system administrator must develop a process notify appropriate personnel when accounts are modified.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the modification of operating system user accounts and notifies the system administrator and ISSO of changes. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are modified.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are modified.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25214r500758_chk'
  tag severity: 'medium'
  tag gid: 'V-223541'
  tag rid: 'SV-223541r533198_rule'
  tag stig_id: 'ACF2-OS-000050'
  tag gtitle: 'SRG-OS-000275-GPOS-00105'
  tag fix_id: 'F-25202r500759_fix'
  tag 'documentable'
  tag legacy: ['V-97787', 'SV-106891']
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
