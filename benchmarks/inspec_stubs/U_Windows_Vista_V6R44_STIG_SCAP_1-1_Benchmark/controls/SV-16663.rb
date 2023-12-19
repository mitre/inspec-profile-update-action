control 'SV-16663' do
  title 'Unsigned gadgets must not be installed.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  This setting prevents unsigned gadgets from being installed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Sidebar ->  "Disable unpacking and installation of gadgets that are not digitally signed" to "Enabled".

To turn off Windows Sidebar completely, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Sidebar -> "Turn off Windows Sidebar" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15724'
  tag rid: 'SV-16663r3_rule'
  tag gtitle: 'Gadgets – Unsigned Gadgets'
  tag fix_id: 'F-62299r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
