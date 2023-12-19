control 'SV-17029' do
  title 'Built-in Admin Account Status'
  desc 'This check verifies that Windows Vista is configured to disable the built-in administrator account which provides no accountability.'
  desc 'fix', 'Configure the system to disable the built-in administrator account.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-16047'
  tag rid: 'SV-17029r1_rule'
  tag gtitle: 'Built-in Admin Account Status'
  tag fix_id: 'F-16131r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
