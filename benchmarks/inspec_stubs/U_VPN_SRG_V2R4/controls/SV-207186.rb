control 'SV-207186' do
  title 'The Remote Access VPN Gateway and/or client must enforce a policy to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. 

The banner is usually configured in NDM for client presentation as well as local logon.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The VPN gateway must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK". 

This applies to gateways that have the concept of a user account and have the login function residing on the gateway or the gateway acts as a user intermediary.'
  desc 'check', 'If the user/remote client connection banner is the same as the banner configured as part of the NDM SRG, then this is not applicable.

Verify the ALG retains the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and takes explicit actions to log on for further access.

If the Remote Access VPN Gateway and/or client does not retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'Configure the Remote Access VPN Gateway and/or client to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7446r378179_chk'
  tag severity: 'medium'
  tag gid: 'V-207186'
  tag rid: 'SV-207186r608988_rule'
  tag stig_id: 'SRG-NET-000042-VPN-000120'
  tag gtitle: 'SRG-NET-000042'
  tag fix_id: 'F-7446r378180_fix'
  tag 'documentable'
  tag legacy: ['V-97045', 'SV-106183']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
