control 'SV-234291' do
  title 'The UEM server must automatically audit account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account disabling actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server automatically audits account disabling actions.

If the UEM server does not automatically audit account disabling actions, this is a finding.'
  desc 'fix', 'Configure the UEM server to automatically audit account disabling actions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37476r613883_chk'
  tag severity: 'medium'
  tag gid: 'V-234291'
  tag rid: 'SV-234291r617355_rule'
  tag stig_id: 'SRG-APP-000028-UEM-000017'
  tag gtitle: 'SRG-APP-000028'
  tag fix_id: 'F-37441r613884_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
