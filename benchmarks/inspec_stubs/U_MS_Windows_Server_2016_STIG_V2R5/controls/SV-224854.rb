control 'SV-224854' do
  title 'The Telnet Client must not be installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.'
  desc 'check', 'Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Telnet-Client".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'
  desc 'fix', 'Uninstall the "Telnet Client" feature.

Start "Server Manager".

Select the server with the feature.

Scroll down to "ROLES AND FEATURES" in the right pane.

Select "Remove Roles and Features" from the drop-down "TASKS" list.

Select the appropriate server on the "Server Selection" page and click "Next".

Deselect "Telnet Client" on the "Features" page.

Click "Next" and "Remove" as prompted.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26545r465464_chk'
  tag severity: 'medium'
  tag gid: 'V-224854'
  tag rid: 'SV-224854r569186_rule'
  tag stig_id: 'WN16-00-000390'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-26533r465465_fix'
  tag 'documentable'
  tag legacy: ['V-73295', 'SV-87947']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
