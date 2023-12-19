control 'SV-224856' do
  title 'The Server Message Block (SMB) v1 protocol must be uninstalled.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant.'
  desc 'check', 'Different methods are available to disable SMBv1 on Windows 2016.  This is the preferred method, however if V-78123 and V-78125 are configured, this is NA.

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
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26547r465470_chk'
  tag severity: 'medium'
  tag gid: 'V-224856'
  tag rid: 'SV-224856r569186_rule'
  tag stig_id: 'WN16-00-000410'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26535r465471_fix'
  tag 'documentable'
  tag legacy: ['V-73299', 'SV-87951']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
