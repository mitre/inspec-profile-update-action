control 'SV-95177' do
  title 'Windows PowerShell must be updated to a version that supports script block logging on Windows 2008 R2.'
  desc 'Later versions of Windows PowerShell provide additional security and advanced logging features that can provide greater detail when malware has been run on a system.  PowerShell 5.x includes the advanced logging features. PowerShell 4.0 with the addition of patch KB3109118 on Windows 2008 R2 adds advanced logging features.

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

If the value for "PSVersion" is not 4.0 or 5.x, this is a finding.'
  desc 'fix', 'Update Windows PowerShell to version 4.0 or 5.x.  

Windows 2008 R2 requires the installation of .NET Framework 4.5 or greater and Windows Management Framework (WMF) 4.0, 5.0, or 5.1. 

Updating to a later PowerShell version may have compatibility issues with some applications. The following links should be reviewed and updates tested before applying to a production environment.

WMF 4.0:
Review the System Requirements under the download link - https://www.microsoft.com/en-us/download/details.aspx?id=40855

WMF 5.0:
https://docs.microsoft.com/en-us/powershell/wmf/5.0/productincompat

WMF 5.1:
https://docs.microsoft.com/en-us/powershell/wmf/5.1/productincompat'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-80145r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80473'
  tag rid: 'SV-95177r1_rule'
  tag stig_id: 'WIN00-000200'
  tag gtitle: 'WIN00-000200'
  tag fix_id: 'F-87279r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
