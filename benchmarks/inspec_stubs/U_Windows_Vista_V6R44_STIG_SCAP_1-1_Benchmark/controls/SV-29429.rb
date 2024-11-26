control 'SV-29429' do
  title 'Prohibit Network Bridge in Windows'
  desc 'This check verifies the Network Bridge can not be installed and configured.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections “Prohibit installation and configuration of Network Bridge on your DNS domain network” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15667'
  tag rid: 'SV-29429r1_rule'
  tag gtitle: 'Prohibit Network Bridge'
  tag fix_id: 'F-15533r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
