control 'SV-205682' do
  title 'Windows Server 2019 must not have the Server Message Block (SMB) v1 protocol installed.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant.'
  desc 'check', 'Different methods are available to disable SMBv1 on Windows Server 2019. This is the preferred method; however, if WN19-00-000390 and WN19-00-000400 are configured, this is NA.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Get-WindowsFeature -Name FS-SMB1".

If "Installed State" is "Installed", this is a finding.

An Installed State of "Available" or "Removed" is not a finding.'
  desc 'fix', 'Uninstall the SMBv1 protocol.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Uninstall-WindowsFeature -Name FS-SMB1 -Restart".
(Omit the Restart parameter if an immediate restart of the system cannot be done.)

Alternately:

Start "Server Manager".

Select the server with the feature.

Scroll down to "ROLES AND FEATURES" in the right pane.

Select "Remove Roles and Features" from the drop-down "TASKS" list.

Select the appropriate server on the "Server Selection" page and click "Next".

Deselect "SMB 1.0/CIFS File Sharing Support" on the "Features" page.

Click "Next" and "Remove" as prompted.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5947r819710_chk'
  tag severity: 'medium'
  tag gid: 'V-205682'
  tag rid: 'SV-205682r819711_rule'
  tag stig_id: 'WN19-00-000380'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-5947r354965_fix'
  tag 'documentable'
  tag legacy: ['V-93391', 'SV-103477']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
