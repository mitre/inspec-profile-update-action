control 'SV-254278' do
  title 'Windows Server 2022 must not have Windows PowerShell 2.0 installed.'
  desc 'Windows PowerShell 5.x added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.x script block logging feature.'
  desc 'check', 'Open "PowerShell".

Enter "Get-WindowsFeature | Where Name -eq PowerShell-v2".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'
  desc 'fix', 'Uninstall the "Windows PowerShell 2.0 Engine".

Start "Server Manager".

Select the server with the feature.

Scroll down to "ROLES AND FEATURES" in the right pane.

Select "Remove Roles and Features" from the drop-down "TASKS" list.

Select the appropriate server on the "Server Selection" page and click "Next".

Deselect "Windows PowerShell 2.0 Engine" under "Windows PowerShell" on the "Features" page.

Click "Next" and "Remove" as prompted.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57763r848648_chk'
  tag severity: 'medium'
  tag gid: 'V-254278'
  tag rid: 'SV-254278r848650_rule'
  tag stig_id: 'WN22-00-000410'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57714r848649_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
