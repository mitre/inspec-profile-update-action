control 'SV-234441' do
  title 'The UEM server must notify system administrators and the Information System Security Officer (ISSO) for account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Accounts are utilized for identifying users or for identifying the application processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server notifies system administrators and the ISSO for account removal actions.

If the UEM server does not notify system administrators and the ISSO for account removal actions, this is a finding.'
  desc 'fix', 'Configure the UEM server to notify system administrators and the ISSO for account removal actions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37626r617414_chk'
  tag severity: 'medium'
  tag gid: 'V-234441'
  tag rid: 'SV-234441r879672_rule'
  tag stig_id: 'SRG-APP-000294-UEM-000168'
  tag gtitle: 'SRG-APP-000294'
  tag fix_id: 'F-37591r614334_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
