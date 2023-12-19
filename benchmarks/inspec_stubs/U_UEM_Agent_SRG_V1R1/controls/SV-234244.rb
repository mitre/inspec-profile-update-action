control 'SV-234244' do
  title 'The UEM Agent must perform the following functions: Import the certificates to be used for authentication of UEM Agent communications.'
  desc 'It is critical that the UEM agent only use validated certificates for policy updates. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy.

'
  desc 'check', 'Verify the UEM Agent performs the following functions: Import the certificates to be used for authentication of UEM Agent communications.

If the UEM Agent does not perform the following functions: Import the certificates to be used for authentication of UEM Agent communications, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to perform the following functions: Import the certificates to be used for authentication of UEM Agent communications.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37429r612038_chk'
  tag severity: 'medium'
  tag gid: 'V-234244'
  tag rid: 'SV-234244r617354_rule'
  tag stig_id: 'SRG-APP-000427-UEM-100009'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-37394r612039_fix'
  tag satisfies: ['FMT_SMF_EXT.4.1']
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
