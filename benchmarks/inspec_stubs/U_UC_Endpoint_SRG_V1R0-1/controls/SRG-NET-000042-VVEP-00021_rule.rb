control 'SRG-NET-000042-VVEP-00021_rule' do
  title 'The Unified Communications Endpoint must be configured to retain the Standard Mandatory DOD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DOD will not be in compliance with system use notifications required by law. 

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK". 

This requirement applies to network elements that have the concept of a user account and have the logon function residing on the network element.'
  desc 'check', 'If the Unified Communications Endpoint is not configured to retain the Standard Mandatory DOD Notice and Consent Banner on the screen until users take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to retain the Standard Mandatory DOD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000042-VVEP-00021_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000042-VVEP-00021'
  tag rid: 'SRG-NET-000042-VVEP-00021_rule'
  tag stig_id: 'SRG-NET-000042-VVEP-00021'
  tag gtitle: 'SRG-NET-000042-VVEP-00021'
  tag fix_id: 'F-SRG-NET-000042-VVEP-00021_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
