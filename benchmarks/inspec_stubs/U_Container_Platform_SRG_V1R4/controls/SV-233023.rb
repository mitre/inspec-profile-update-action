control 'SV-233023' do
  title 'The container platform must automatically audit account modification.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application when accounts are created. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the container platform configuration to determine if account modification is automatically audited. 

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically audit account modification.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35959r600556_chk'
  tag severity: 'medium'
  tag gid: 'V-233023'
  tag rid: 'SV-233023r879526_rule'
  tag stig_id: 'SRG-APP-000027-CTR-000075'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-35927r600557_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
