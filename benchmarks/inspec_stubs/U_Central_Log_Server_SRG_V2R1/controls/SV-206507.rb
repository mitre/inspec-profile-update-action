control 'SV-206507' do
  title 'The Central Log Server must be configured to electronically verify the DoD CAC credential.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to accept the DoD CAC credentials to support identity management and personal authentication.

If the Central Log Server cannot be configured to accept the DoD CAC credentials to support identity management and personal authentication, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to accept the DoD CAC credentials to support identity management and personal authentication.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6767r285762_chk'
  tag severity: 'medium'
  tag gid: 'V-206507'
  tag rid: 'SV-206507r400042_rule'
  tag stig_id: 'SRG-APP-000392-AU-002300'
  tag gtitle: 'SRG-APP-000392'
  tag fix_id: 'F-6767r285763_fix'
  tag 'documentable'
  tag legacy: ['SV-96041', 'V-81327']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
