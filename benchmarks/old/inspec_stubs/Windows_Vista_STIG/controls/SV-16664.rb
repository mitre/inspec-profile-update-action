control 'SV-16664' do
  title 'The More Gadgets link must be disabled.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  This setting prevents access to gadgets through the More Gadgets link.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Sidebar -> "Override the More Gadgets Link" to "Enabled" with "about:blank" entered in the "Override Gadget Location".   

To turn off Windows Sidebar completely, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Sidebar -> "Turn off Windows Sidebar" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15725'
  tag rid: 'SV-16664r3_rule'
  tag gtitle: 'Gadgets – More Gadgets Link'
  tag fix_id: 'F-62301r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
