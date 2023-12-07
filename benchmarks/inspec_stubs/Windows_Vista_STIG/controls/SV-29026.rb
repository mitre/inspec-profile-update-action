control 'SV-29026' do
  title 'The Windows SMB server is not enabled to perform SMB packet signing when possible.'
  desc 'If this policy is enabled, it causes the Windows Server Message Block (SMB) server to perform SMB packet signing.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Server: Digitally sign communications (if Client agrees)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1162'
  tag rid: 'SV-29026r1_rule'
  tag gtitle: 'SMB Server Packet Signing (if client agrees)'
  tag fix_id: 'F-104r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
