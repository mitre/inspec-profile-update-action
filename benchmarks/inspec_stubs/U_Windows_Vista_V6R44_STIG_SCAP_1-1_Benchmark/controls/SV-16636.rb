control 'SV-16636' do
  title 'Network – Responder Driver'
  desc 'This check verifies that the Responder network protocol driver is disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery “Turn on Responder (RSPNDR) driver” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15697'
  tag rid: 'SV-16636r1_rule'
  tag gtitle: 'Network – Responder Driver'
  tag fix_id: 'F-15589r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
