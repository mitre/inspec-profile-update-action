control 'SV-16665' do
  title 'User-installed gadgets must be turned off.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  This setting prevents user-installed gadgets from running.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Sidebar -> "Turn Off User Installed Windows Sidebar Gadgets" to "Enabled".

To turn off Windows Sidebar completely, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Sidebar -> "Turn off Windows Sidebar" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15726'
  tag rid: 'SV-16665r3_rule'
  tag gtitle: 'Gadgets – User Installed Gadgets'
  tag fix_id: 'F-62303r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
