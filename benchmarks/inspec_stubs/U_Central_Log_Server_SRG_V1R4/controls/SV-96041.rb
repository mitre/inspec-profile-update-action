control 'SV-96041' do
  title 'The Central Log Server must be configured to electronically verify the DoD CAC credential.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to accept the DoD CAC credentials to support identity management and personal authentication.

If the Central Log Server cannot be configured to accept the DoD CAC credentials to support identity management and personal authentication, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to accept the DoD CAC credentials to support identity management and personal authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81031r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81327'
  tag rid: 'SV-96041r1_rule'
  tag stig_id: 'SRG-APP-000392-AU-002300'
  tag gtitle: 'SRG-APP-000392-AU-002300'
  tag fix_id: 'F-88111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
