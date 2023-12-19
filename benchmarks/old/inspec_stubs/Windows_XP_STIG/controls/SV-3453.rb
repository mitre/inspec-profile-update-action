control 'SV-3453' do
  title 'Terminal Services is not configured to always prompt a client for passwords upon connection.'
  desc 'This setting, which is located under the Encryption and Security section of the Terminal Services configuration option, controls the ability of users to supply passwords automatically as part of their Remote Desktop Connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Encryption and Security “Always Prompt Client for Password upon Connection”  to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3453'
  tag rid: 'SV-3453r1_rule'
  tag gtitle: 'TS/RDS - Password Prompting'
  tag fix_id: 'F-5922r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
