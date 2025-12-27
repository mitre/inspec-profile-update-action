control 'SV-83307' do
  title 'The Fax service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Run "Services.msc".

If the "Fax" service (Service name: Fax) is installed and not disabled, this is a finding.'
  desc 'fix', 'Remove or disable the "Fax" service (Service name: fax).   

To remove the "Fax Server" role from a system:
Start "Server Manager"
Select "Roles" in the left pane.
Under "Role Summary" in the right pane, select "Remove Roles".
On the "Server Roles" screen, de-select "Fax Server".
Click "Next" and "Remove".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-69257r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26600'
  tag rid: 'SV-83307r1_rule'
  tag stig_id: 'WINSV-000100'
  tag gtitle: 'Fax Service Disabled'
  tag fix_id: 'F-74865r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
