control 'SV-234466' do
  title 'The UEM server must notify system administrator and Information System Security Officer (ISSO) of account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server notifies the system administrator and the ISSO of account enabling actions.

If the UEM server does not notify the system administrator and the ISSO of account enabling actions, this is a finding.'
  desc 'fix', 'Configure the UEM server to notify system administrator and the ISSO of account enabling actions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37651r617399_chk'
  tag severity: 'medium'
  tag gid: 'V-234466'
  tag rid: 'SV-234466r617399_rule'
  tag stig_id: 'SRG-APP-000320-UEM-000193'
  tag gtitle: 'SRG-APP-000320'
  tag fix_id: 'F-37616r614409_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
