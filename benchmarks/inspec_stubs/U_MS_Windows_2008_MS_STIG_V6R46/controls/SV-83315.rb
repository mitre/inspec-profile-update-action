control 'SV-83315' do
  title 'The Telnet service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Run "Services.msc".

If the "Telnet" service (Service name: TlntSvr) is installed and not disabled, this is a finding.'
  desc 'fix', 'Remove or disable the "Telnet" service (Service name: TlntSvr).   

To remove the "Telnet" service from a system:
Start "Server Manager"
Select "Features" in the left pane.
Under "Features Summary" in the right pane, select "Remove Features".
On the "Features" screen, de-select "Telnet Server".
Click "Next" and "Remove".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-69265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26606'
  tag rid: 'SV-83315r1_rule'
  tag stig_id: 'WINSV-000105'
  tag gtitle: 'Telnet Service Disabled'
  tag fix_id: 'F-74873r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
