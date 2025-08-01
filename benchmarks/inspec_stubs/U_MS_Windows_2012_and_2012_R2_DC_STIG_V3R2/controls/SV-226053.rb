control 'SV-226053' do
  title 'Windows PowerShell must be updated to a version that supports script block logging on Windows 2012/2012 R2.'
  desc 'Later versions of Windows PowerShell provide additional security and advanced logging features that can provide greater detail when malware has been run on a system.  PowerShell 5.x includes the advanced logging features. PowerShell 4.0 with the addition of patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 adds advanced logging features.

PowerShell is updated with the installation of the corresponding version of the Windows Management Framework (WMF).

Updating to a later PowerShell version may have compatibility issues with some applications.  The following links should be reviewed and updates tested before applying to a production environment.

WMF 4.0:
Review the System Requirements under the download link - https://www.microsoft.com/en-us/download/details.aspx?id=40855

WMF 5.0:
https://docs.microsoft.com/en-us/powershell/wmf/5.0/productincompat

WMF 5.1:
https://docs.microsoft.com/en-us/powershell/wmf/5.1/productincompat'
  desc 'check', 'Open "Windows PowerShell".

Enter "$PSVersionTable".

If the value for "PSVersion" is not 4.0 or 5.x, this is a finding.

Windows 2012 R2 includes PowerShell 4.0 by default. Windows 2012 must be updated. If PowerShell 4.0 is used, the required patch for script block logging will be verified with the requirement to have that enabled.'
  desc 'fix', 'Update Windows PowerShell to version 4.0 or 5.x.  

Windows 2012 R2 includes PowerShell 4.0 by default. It may be updated with the installation of Windows Management Framework (WMF) 5.0 or 5.1.

Windows 2012 requires the installation of Windows Management Framework (WMF) 4.0, 5.0, or 5.1.

Updating to a later PowerShell version may have compatibility issues with some applications. The following links should be reviewed and updates tested before applying to a production environment.

WMF 4.0:
Review the System Requirements under the download link - https://www.microsoft.com/en-us/download/details.aspx?id=40855

WMF 5.0:
https://docs.microsoft.com/en-us/powershell/wmf/5.0/productincompat

WMF 5.1:
https://docs.microsoft.com/en-us/powershell/wmf/5.1/productincompat'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27755r475482_chk'
  tag severity: 'medium'
  tag gid: 'V-226053'
  tag rid: 'SV-226053r569184_rule'
  tag stig_id: 'WN12-00-000200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27743r475483_fix'
  tag 'documentable'
  tag legacy: ['SV-95179', 'V-80473']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
