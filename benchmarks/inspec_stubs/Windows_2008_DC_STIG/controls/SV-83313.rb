control 'SV-83313' do
  title 'The Simple TCP/IP Services service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Run "Services.msc".

If "Simple TCP/IP Services" (Service name: simptcp) is installed and not disabled, this is a finding.'
  desc 'fix', 'Remove or disable "Simple TCP/IP Services" (Service name: simptcp).   

To remove "Simple TCP/IP Services" from a system:
Start "Server Manager"
Select "Features" in the left pane.
Under "Features Summary" in the right pane, select "Remove Features".
On the "Features" screen, de-select "Simple TCP/IP Services".
Click "Next" and "Remove".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-69263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26605'
  tag rid: 'SV-83313r1_rule'
  tag stig_id: 'WINSV-000104'
  tag gtitle: 'Simple TCP/IP Services Disabled'
  tag fix_id: 'F-74871r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
