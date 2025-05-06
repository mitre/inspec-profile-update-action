control 'SV-14860' do
  title 'Terminal Services / Remote Desktop Services - Local drives prevented from sharing with Terminal Servers.'
  desc 'This check verifies that the system is configured to prevent users from sharing the local drives on their client computers to Terminal Servers that they access.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Device and Resource Redirection “Do not allow drive redirection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14249'
  tag rid: 'SV-14860r1_rule'
  tag gtitle: 'TS/RDS - Drive Redirection'
  tag fix_id: 'F-13574r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
