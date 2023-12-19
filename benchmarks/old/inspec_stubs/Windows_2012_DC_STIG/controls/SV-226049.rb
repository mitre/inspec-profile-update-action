control 'SV-226049' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on Windows 2012 R2.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only support SMBv1.'
  desc 'check', 'This requirement applies to Windows 2012 R2, it is NA for Windows 2012 (see V-73519 and V-73523 for 2012 requirements).

Different methods are available to disable SMBv1 on Windows 2012 R2.  This is the preferred method, however if V-73519 and V-73523 are configured, this is NA.

Run "Windows PowerShell" with elevated privileges (run as administrator).
Enter the following:
Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol

If "State : Enabled" is returned, this is a finding.

Alternately:
Search for "Features".
Select "Turn Windows features on or off".

If "SMB 1.0/CIFS File Sharing Support" is selected, this is a finding.'
  desc 'fix', 'Run "Windows PowerShell" with elevated privileges (run as administrator).
Enter the following:
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

Alternately:
Search for "Features".
Select "Turn Windows features on or off".
De-select "SMB 1.0/CIFS File Sharing Support". 

The system must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27751r475470_chk'
  tag severity: 'medium'
  tag gid: 'V-226049'
  tag rid: 'SV-226049r794699_rule'
  tag stig_id: 'WN12-00-000160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27739r794698_fix'
  tag 'documentable'
  tag legacy: ['V-73805', 'SV-88471']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
