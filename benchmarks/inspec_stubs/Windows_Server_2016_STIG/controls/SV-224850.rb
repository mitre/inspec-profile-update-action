control 'SV-224850' do
  title 'The Fax Server role must not be installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system.'
  desc 'check', 'Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq Fax".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'
  desc 'fix', 'Uninstall the "Fax Server" role.

Start "Server Manager".

Select the server with the role.

Scroll down to "ROLES AND FEATURES" in the right pane.

Select "Remove Roles and Features" from the drop-down "TASKS" list.

Select the appropriate server on the "Server Selection" page and click "Next".

Deselect "Fax Server" on the "Roles" page.

Click "Next" and "Remove" as prompted.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26541r465452_chk'
  tag severity: 'medium'
  tag gid: 'V-224850'
  tag rid: 'SV-224850r569186_rule'
  tag stig_id: 'WN16-00-000350'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26529r465453_fix'
  tag 'documentable'
  tag legacy: ['V-73287', 'SV-87939']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
