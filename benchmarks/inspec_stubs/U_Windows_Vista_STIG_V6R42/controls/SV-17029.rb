control 'SV-17029' do
  title 'Built-in Admin Account Status'
  desc 'This check verifies that Windows Vista is configured to disable the built-in administrator account which provides no accountability.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Accounts: Administrator account status” is not set to "Disabled”, then this is a finding.'
  desc 'fix', 'Configure the system to disable the built-in administrator account.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-17016r1_chk'
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
