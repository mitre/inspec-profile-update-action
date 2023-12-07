control 'SV-18404' do
  title 'Built-in Admin Account Status'
  desc 'This check verifies that Windows XP is configured to ensure the built-in administrator account is enabled.'
  desc 'fix', 'Configure the system to enable the built-in admin account.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-16047'
  tag rid: 'SV-18404r1_rule'
  tag gtitle: 'Built-in Admin Account Status'
  tag fix_id: 'F-17257r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
end
