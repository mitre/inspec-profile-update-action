control 'SV-29613' do
  title 'Order Prints Online'
  desc 'This check verifies that the “Order Prints Online” task is not available in Windows Explorer.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off the “Order Prints” picture task” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15676'
  tag rid: 'SV-29613r1_rule'
  tag gtitle: 'Order Prints Online'
  tag fix_id: 'F-15543r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
