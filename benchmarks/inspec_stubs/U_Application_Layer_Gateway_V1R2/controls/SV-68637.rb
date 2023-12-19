control 'SV-68637' do
  title 'The ALG providing user access control intermediary services must retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG retains the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and takes explicit actions to log on for further access.

If the ALG does not retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55007r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54391'
  tag rid: 'SV-68637r1_rule'
  tag stig_id: 'SRG-NET-000042-ALG-000023'
  tag gtitle: 'SRG-NET-000042-ALG-000023'
  tag fix_id: 'F-59245r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
