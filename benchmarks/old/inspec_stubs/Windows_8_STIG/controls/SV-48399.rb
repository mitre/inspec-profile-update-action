control 'SV-48399' do
  title 'The Windows 8 default Communications apps (Mail, People, Messaging, and Calendar) must be updated with the latest security patches or removed from the system.'
  desc 'Applications must be updated as flaws are identified and remediations are made available. The default method for updating Windows 8 apps is through the Windows Store, which is required to be blocked.  An alternate method must be used to maintain the default Windows 8 apps with the latest security updates if they are allowed on a system.'
  desc 'check', 'Verify the default Communications apps have been patched with the latest security related updates or removed from the system.

Open a command prompt as an administrator.
Enter "dism /online /Get-ProvisionedAppxPackages".
If "DisplayName : microsoft.windowscommunicationsapps" is listed and has not been updated with the latest security related updates, this is a finding.

The "PackageName" field will identify the version installed.

Microsoft Article 2971128 summarizes security related updates to the default apps, including versions and release dates.  http://support.microsoft.com/kb/2971128'
  desc 'fix', 'Maintain the Communications apps with the latest security related updates or remove them from the system.  Microsoft provides security related updates to default provisioned apps through the Microsoft Update Catalog for WSUS or as MSI files, as an alternate method to the Windows Store for updating.

Microsoft Article 2971128 summarizes security related updates to the default apps, including versions and release dates.  http://support.microsoft.com/kb/2971128

To remove the Communications apps from the system:

Open a command prompt as an administrator.
Enter "dism /online /Get-ProvisionedAppxPackages".
Make note of the PackageName (e.g., microsoft.windowscommunicationsapps_16.4.4206.722_x64__8wekyb3d8bbwe).
Enter the following to remove the app package from the system: "dism /online /Remove-ProvisionedAppxPackage /PackageName:packagename", substituting "packagename" noted from the previous step.
Uninstall the application from any user profiles provisioned prior to this.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-57803r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36750'
  tag rid: 'SV-48399r5_rule'
  tag stig_id: 'WN08-GE-000045'
  tag gtitle: 'WN08-GE-000045'
  tag fix_id: 'F-62127r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
