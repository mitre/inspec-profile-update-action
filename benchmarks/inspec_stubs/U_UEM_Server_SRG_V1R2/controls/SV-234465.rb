control 'SV-234465' do
  title 'The UEM server must automatically audit account-enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Automatically auditing account enabling actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server automatically audits account enabling actions.

If the UEM server does not automatically audit account enabling actions, this is a finding.'
  desc 'fix', 'Configure the UEM server to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37650r614405_chk'
  tag severity: 'medium'
  tag gid: 'V-234465'
  tag rid: 'SV-234465r879696_rule'
  tag stig_id: 'SRG-APP-000319-UEM-000192'
  tag gtitle: 'SRG-APP-000319'
  tag fix_id: 'F-37615r614406_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
