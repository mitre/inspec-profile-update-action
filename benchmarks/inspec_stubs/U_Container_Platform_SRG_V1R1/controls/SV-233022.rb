control 'SV-233022' do
  title 'The container platform must automatically audit account creation.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to create a new account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application when accounts are created. Such a process greatly reduces the risk that accounts will be surreptitiously created, and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the container platform configuration to determine if audit records are automatically created upon account creation. 

If audit records are not automatically created upon account creation, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically create audit records on account creation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35958r598702_chk'
  tag severity: 'medium'
  tag gid: 'V-233022'
  tag rid: 'SV-233022r599509_rule'
  tag stig_id: 'SRG-APP-000026-CTR-000070'
  tag gtitle: 'SRG-APP-000026'
  tag fix_id: 'F-35926r598703_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
