control 'SV-215742' do
  title 'The BIG-IP Core implementation must be configured to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users accessing virtual servers acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to virtual servers. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an access policy to retain the Standard Mandatory DoD-approved Notice and Consent Banner.

If the BIG-IP Core is not configured to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access. 

Apply the APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16934r291039_chk'
  tag severity: 'low'
  tag gid: 'V-215742'
  tag rid: 'SV-215742r557356_rule'
  tag stig_id: 'F5BI-LT-000025'
  tag gtitle: 'SRG-NET-000042-ALG-000023'
  tag fix_id: 'F-16932r291040_fix'
  tag 'documentable'
  tag legacy: ['V-60265', 'SV-74695']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
