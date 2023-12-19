control 'SV-85915' do
  title 'The CA API Gateway providing user access control intermediary services must retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

The CA API Gateway should return a custom template response before routing to a back-end service with the above DoD Banner and must wait for acceptance of the Banner by the requesting user. An application should be set up to call a CA API Gateway Service with the custom response included that, before logon of an application, displays the Standard Mandatory DoD-approved Notice and Consent Banner.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and verify a Registered Service is present for displaying the Standard Mandatory DoD-approved Notice and Consent Banner. 

If the Registered Service is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and create a Registered Service that includes a "Return Template Response" Assertion displaying the Standard Mandatory DoD-approved Notice and Consent Banner. 

Add additional policy Assertions to check for whether the banner was acknowledged or not and grant access accordingly to the logon page. 

For more details, refer to the "Layer 7 Policy Authoring User Manual".'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71291'
  tag rid: 'SV-85915r1_rule'
  tag stig_id: 'CAGW-GW-000140'
  tag gtitle: 'SRG-NET-000042-ALG-000023'
  tag fix_id: 'F-77597r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
