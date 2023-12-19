control 'SV-1084' do
  title 'System pagefile is cleared upon shutdown.'
  desc 'This check verifies that Windows is not configured to wipe clean the system page file during a controlled system shutdown.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Shutdown: Clear virtual memory pagefile” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1084'
  tag rid: 'SV-1084r1_rule'
  tag gtitle: 'Clear System Pagefile'
  tag fix_id: 'F-6897r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECRC-1'
end
