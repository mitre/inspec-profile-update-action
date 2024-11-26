control 'SV-224852' do
  title 'The Peer Name Resolution Protocol must not be installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.'
  desc 'check', 'Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq PNRP".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'
  desc 'fix', 'Uninstall the "Peer Name Resolution Protocol" feature.

Start "Server Manager".

Select the server with the feature.

Scroll down to "ROLES AND FEATURES" in the right pane.

Select "Remove Roles and Features" from the drop-down "TASKS" list.

Select the appropriate server on the "Server Selection" page and click "Next".

Deselect "Peer Name Resolution Protocol" on the "Features" page.

Click "Next" and "Remove" as prompted.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26543r465458_chk'
  tag severity: 'medium'
  tag gid: 'V-224852'
  tag rid: 'SV-224852r569186_rule'
  tag stig_id: 'WN16-00-000370'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26531r465459_fix'
  tag 'documentable'
  tag legacy: ['V-73291', 'SV-87943']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
