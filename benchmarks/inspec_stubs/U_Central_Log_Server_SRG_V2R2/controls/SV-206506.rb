control 'SV-206506' do
  title 'The Central Log Server must be configured to accept the DoD CAC credential to support identity management and personal authentication.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

If the application cannot meet this requirement, the risk may be mitigated through use of an authentication server.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to accept the DoD CAC credential to support identity management and personal authentication.

If the Central Log Server cannot be configured to accept the DoD CAC credential to support identity management and personal authentication, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to accept the DoD CAC credential to support identity management and personal authentication.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6766r285759_chk'
  tag severity: 'medium'
  tag gid: 'V-206506'
  tag rid: 'SV-206506r855313_rule'
  tag stig_id: 'SRG-APP-000391-AU-002290'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-6766r285760_fix'
  tag 'documentable'
  tag legacy: ['SV-96037', 'V-81323']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
