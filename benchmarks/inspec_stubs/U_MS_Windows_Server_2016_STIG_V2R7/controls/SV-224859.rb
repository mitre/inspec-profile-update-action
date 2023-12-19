control 'SV-224859' do
  title 'Windows PowerShell 2.0 must not be installed.'
  desc 'Windows PowerShell 5.0 added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.'
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
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26550r465479_chk'
  tag severity: 'medium'
  tag gid: 'V-224859'
  tag rid: 'SV-224859r569186_rule'
  tag stig_id: 'WN16-00-000420'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26538r465480_fix'
  tag 'documentable'
  tag legacy: ['SV-87953', 'V-73301']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
