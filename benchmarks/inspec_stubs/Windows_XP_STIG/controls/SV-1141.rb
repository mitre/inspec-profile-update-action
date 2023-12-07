control 'SV-1141' do
  title 'Unencrypted password is sent to 3rd party SMB Server.'
  desc 'Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the Vendor of the SMB server to see if there is a way to support encrypted password authentication.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Client: Send unencrypted password to connect to third-party SMB servers” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1141'
  tag rid: 'SV-1141r1_rule'
  tag gtitle: 'Unencrypted Password is Sent to SMB Server.'
  tag fix_id: 'F-93r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCT-1, ECCT-2'
end
