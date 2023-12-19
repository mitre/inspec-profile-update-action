control 'SV-234292' do
  title 'The UEM server must automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server automatically audits account removal actions.

If the UEM server does not automatically audit account removal actions, this is a finding.'
  desc 'fix', 'Configure the UEM server to automatically audit account removal actions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37477r613886_chk'
  tag severity: 'medium'
  tag gid: 'V-234292'
  tag rid: 'SV-234292r879528_rule'
  tag stig_id: 'SRG-APP-000029-UEM-000018'
  tag gtitle: 'SRG-APP-000029'
  tag fix_id: 'F-37442r613887_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
