control 'SV-29277' do
  title 'Terminal Services is not configured to always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their Remote Desktop Connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Security “Always Prompt Client for Password upon Connection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3453'
  tag rid: 'SV-29277r2_rule'
  tag gtitle: 'TS/RDS - Password Prompting'
  tag fix_id: 'F-36075r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
