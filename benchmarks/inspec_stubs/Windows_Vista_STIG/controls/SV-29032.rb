control 'SV-29032' do
  title 'The Windows SMB client is not enabled to perform SMB packet signing when possible.'
  desc 'If this policy is enabled, it causes the Windows Server Message Block (SMB) client to perform SMB packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Client: Digitally sign communications (if server agrees)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1166'
  tag rid: 'SV-29032r1_rule'
  tag gtitle: 'SMB Client Packet Signing (if server agrees)'
  tag fix_id: 'F-103r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
