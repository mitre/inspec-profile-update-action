control 'SV-16635' do
  title 'Network – Mapper I/O Driver'
  desc 'This check verifies that the Mapper I/O network protocol driver is disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery “Turn on Mapper I/O (LLTDIO) driver” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15696'
  tag rid: 'SV-16635r1_rule'
  tag gtitle: 'Network – Mapper I/O Driver'
  tag fix_id: 'F-15588r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
