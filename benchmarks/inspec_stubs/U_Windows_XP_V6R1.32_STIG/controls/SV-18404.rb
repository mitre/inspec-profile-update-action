control 'SV-18404' do
  title 'Built-in Admin Account Status'
  desc 'This check verifies that Windows XP is configured to ensure the built-in administrator account is enabled.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. Navigate to Local Policies -> Security Options. If the value for “Accounts: Administrator account status” is not set to ” Enabled”, then this is a finding.'
  desc 'fix', 'Configure the system to enable the built-in admin account.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-18059r1_chk'
  tag severity: 'low'
  tag gid: 'V-16047'
  tag rid: 'SV-18404r1_rule'
  tag gtitle: 'Built-in Admin Account Status'
  tag fix_id: 'F-17257r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
end
