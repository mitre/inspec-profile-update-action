control 'SV-95539' do
  title 'AAA Services must be configured to automatically audit account creation.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of user accounts and, as required, notifies administrators and/or managers. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to automatically audit account creation.

If AAA Services are not configured to automatically audit account creation, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically audit account creation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80565r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80829'
  tag rid: 'SV-95539r1_rule'
  tag stig_id: 'SRG-APP-000026-AAA-000090'
  tag gtitle: 'SRG-APP-000026-AAA-000090'
  tag fix_id: 'F-87683r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
