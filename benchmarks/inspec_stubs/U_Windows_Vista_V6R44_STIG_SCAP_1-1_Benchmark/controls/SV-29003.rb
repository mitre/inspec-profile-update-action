control 'SV-29003' do
  title 'Unencrypted passwords must not be sent to third-party SMB Servers.'
  desc 'Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the Vendor of the SMB server to see if there is a way to support encrypted password authentication.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1141'
  tag rid: 'SV-29003r2_rule'
  tag gtitle: 'Unencrypted Password is Sent to SMB Server.'
  tag fix_id: 'F-66891r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
