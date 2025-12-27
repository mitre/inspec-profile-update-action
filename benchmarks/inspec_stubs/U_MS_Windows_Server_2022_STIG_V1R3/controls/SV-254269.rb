control 'SV-254269' do
  title 'Windows Server 2022 must not have the Fax Server role installed.'
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
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57754r848621_chk'
  tag severity: 'medium'
  tag gid: 'V-254269'
  tag rid: 'SV-254269r848623_rule'
  tag stig_id: 'WN22-00-000320'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57705r848622_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
