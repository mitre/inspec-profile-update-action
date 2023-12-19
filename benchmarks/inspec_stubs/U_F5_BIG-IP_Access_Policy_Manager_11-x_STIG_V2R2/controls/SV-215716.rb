control 'SV-215716' do
  title 'The BIG-IP APM module must retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users accessing virtual servers acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the BIG-IP APM module does not provide user access control intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and takes explicit actions to log on for further access.

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for granting access.

Verify the Access Profile is configured to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users accessing virtual servers acknowledge the usage conditions and take explicit actions to log on for further access.

If the BIG-IP APM module is not configured to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure an access policy in the BIG-IP APM module to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16909r290394_chk'
  tag severity: 'low'
  tag gid: 'V-215716'
  tag rid: 'SV-215716r557355_rule'
  tag stig_id: 'F5BI-AP-000025'
  tag gtitle: 'SRG-NET-000042-ALG-000023'
  tag fix_id: 'F-16907r290395_fix'
  tag 'documentable'
  tag legacy: ['SV-74363', 'V-59933']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
