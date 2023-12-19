control 'SV-206750' do
  title 'The Voice Video Endpoint must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK". System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. This requirement applies to Voice Video Endpoints that have the concept of a user account and have the logon function residing on the network element.'
  desc 'check', 'If the Voice Video Endpoint is a hardware endpoint, this is Not Applicable.

If the Voice Video Endpoint is a Unified Capabilities (UC) or Video Conferencing (VC) software client, verify the Voice Video Endpoint retains the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access. 

If the Voice Video Endpoint does not retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'Configure the Unified Capabilities (UC) or Video Conferencing (VC) software client Voice Video Endpoint to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7006r363773_chk'
  tag severity: 'medium'
  tag gid: 'V-206750'
  tag rid: 'SV-206750r604140_rule'
  tag stig_id: 'SRG-NET-000042-VVEP-00021'
  tag gtitle: 'SRG-NET-000042'
  tag fix_id: 'F-7006r363774_fix'
  tag 'documentable'
  tag legacy: ['SV-81215', 'V-66725']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
