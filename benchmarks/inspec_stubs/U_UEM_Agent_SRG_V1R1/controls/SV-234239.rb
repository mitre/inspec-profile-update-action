control 'SV-234239' do
  title 'The UEM Agent must not install policies if the policy-signing certificate is deemed invalid.'
  desc 'It is critical that the UEM agent only use validated certificates for policy updates. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy.

'
  desc 'check', 'Verify the UEM Agent does not install policies if the policy-signing certificate is deemed invalid.

If the UEM Agent installs policies when the policy-signing certificate is deemed invalid, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to not install policies if the policy-signing certificate is deemed invalid.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37424r612023_chk'
  tag severity: 'medium'
  tag gid: 'V-234239'
  tag rid: 'SV-234239r617354_rule'
  tag stig_id: 'SRG-APP-000175-UEM-100008'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-37389r612024_fix'
  tag satisfies: ['FMT_POL_EXT.2.2']
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
