control 'SV-16657' do
  title 'Windows Explorer – Heap Termination'
  desc 'This check verifies that heap termination on corruption is disabled.  This may prevent Windows Explorer from terminating immediately from certain legacy plug-in applications.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Explorer “Turn off heap termination on corruption” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15718'
  tag rid: 'SV-16657r2_rule'
  tag gtitle: 'Windows Explorer – Heap Termination'
  tag fix_id: 'F-15610r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
