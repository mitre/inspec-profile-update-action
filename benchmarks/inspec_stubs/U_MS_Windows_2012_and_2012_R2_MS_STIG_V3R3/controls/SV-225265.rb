control 'SV-225265' do
  title 'Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2.'
  desc 'Windows PowerShell versions 4.0 (with a patch) and 5.x add advanced logging features that can provide additional detail when malware has been run on a system. Ensuring Windows PowerShell 2.0 is not installed as well mitigates against a downgrade attack that evades the advanced logging features of later Windows PowerShell versions.'
  desc 'check', 'Windows PowerShell 2.0 is not installed by default.

Open "Windows PowerShell".

Enter "Get-WindowsFeature -Name PowerShell-v2".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'
  desc 'fix', 'Windows PowerShell 2.0 is not installed by default.

Uninstall it if it has been installed.

Open "Windows PowerShell".

Enter "Uninstall-WindowsFeature -Name PowerShell-v2".

Alternately:

Use the "Remove Roles and Features Wizard" and deselect "Windows PowerShell 2.0 Engine" under "Windows PowerShell".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26964r471137_chk'
  tag severity: 'medium'
  tag gid: 'V-225265'
  tag rid: 'SV-225265r569185_rule'
  tag stig_id: 'WN12-00-000220'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26952r471138_fix'
  tag 'documentable'
  tag legacy: ['SV-95185', 'V-80477']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
