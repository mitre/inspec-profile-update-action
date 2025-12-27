control 'SV-256892' do
  title 'The UEM Server must provide digitally signed policy updates to UEM Agent.'
  desc 'It is critical that the UEM server sign all policy updates with validated certificates. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy.

'
  desc 'check', 'Verify the UEM server is signing all policy updates sent to the UEM Agent with validated certificates.

If the UEM server is not signing all policy updates sent to the UEM Agent with validated certificates, this is a finding.'
  desc 'fix', 'Configure the UEM server to sign all policy updates sent to the UEM Agent with validated certificates.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-60567r891313_chk'
  tag severity: 'medium'
  tag gid: 'V-256892'
  tag rid: 'SV-256892r891314_rule'
  tag stig_id: 'SRG-APP-000427-UEM-000500'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-60510r891311_fix'
  tag satisfies: ['FMT_POL_EXT.1.1']
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
