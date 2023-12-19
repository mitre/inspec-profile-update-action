control 'SV-234440' do
  title 'The UEM server must notify system administrators and the Information System Security Officer (ISSO) for account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server notifies system administrators and the ISSO for account disabling actions.

If the UEM server does not notify system administrators and the ISSO for account disabling actions, this is a finding.'
  desc 'fix', 'Configure the UEM server to notify system administrators and the ISSO for account disabling actions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37625r614330_chk'
  tag severity: 'medium'
  tag gid: 'V-234440'
  tag rid: 'SV-234440r879671_rule'
  tag stig_id: 'SRG-APP-000293-UEM-000167'
  tag gtitle: 'SRG-APP-000293'
  tag fix_id: 'F-37590r614331_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
