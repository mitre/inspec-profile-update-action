control 'SV-83311' do
  title 'The Peer Networking Identity Manager service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'Run "Services.msc".

If the "Peer Networking Identity Manager" service (Service name: p2pimsvc) is installed and not disabled, this is a finding.'
  desc 'fix', 'Remove or disable the "Peer Networking Identity Manager" service (Service name: p2pimsvc).   

The "Peer Networking Identity Manager" service may have been installed to support various functions, such as the "Peer Name Resolution Protocol".
To remove the "Peer Name Resolution Protocol" from a system:
Start "Server Manager"
Select "Features" in the left pane.
Under "Features Summary" in the right pane, select "Remove Features".
On the "Features" screen, de-select "Peer Name Resolution Protocol ".
Click "Next" and "Remove".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-69261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26604'
  tag rid: 'SV-83311r1_rule'
  tag stig_id: 'WINSV-000103'
  tag gtitle: 'Peer Networking Identity Manager Service Disabled'
  tag fix_id: 'F-74869r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
