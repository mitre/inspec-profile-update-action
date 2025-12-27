control 'SV-234438' do
  title 'The UEM server must notify system administrators and the Information System Security Officer (ISSO) when accounts are created.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator and ISSO is one method for mitigating this risk.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server notify system administrators and ISSO when accounts are created.

If the UEM server does not notify system administrators and the ISSO when accounts are created, this is a finding.'
  desc 'fix', 'Configure the UEM server to notify system administrators and the ISSO when accounts are created.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37623r614324_chk'
  tag severity: 'medium'
  tag gid: 'V-234438'
  tag rid: 'SV-234438r617355_rule'
  tag stig_id: 'SRG-APP-000291-UEM-000165'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-37588r614325_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
