control 'SV-29391' do
  title 'The Windows Server SMB server is not enabled to always perform SMB packet signing.'
  desc 'If this policy is enabled, it causes the Windows Server Message Block (SMB) server to always perform SMB packet signing.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Server: Digitally sign communications (always)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-6833'
  tag rid: 'SV-29391r1_rule'
  tag gtitle: 'SMB Server Packet Signing (Always)'
  tag fix_id: 'F-6520r1_fix'
  tag 'documentable'
  tag potential_impacts: 'If the environment is a mixed one, with down-level OSs, or maintains trusts with down-level OSs, then configuring this to the required setting could cause compatibility problems.'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
