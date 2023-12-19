control 'SV-56056' do
  title 'The Windows 8 default Skype app must be removed from the system.'
  desc 'Some Windows 8 default apps provide links to external services and must be removed from the system.'
  desc 'check', 'Verify the Skype app has been removed from the system.
Open a command prompt as an administrator.
Enter "dism /online /Get-ProvisionedAppxPackages".
If "DisplayName : Microsoft.SkypeApp" is listed, this is a finding.'
  desc 'fix', 'Remove the Skype app from the system.
Open a command prompt as an administrator.
Enter "dism /online /Get-ProvisionedAppxPackages".
Make note of the PackageName (e.g., Microsoft.SkypeApp_2013.805.1159.2246_neutral_~_kzf8qxf38zg5c).
Enter the following to remove the app package from the system: "dism /online /Remove-ProvisionedAppxPackage /PackageName:packagename", substituting "packagename" noted from the previous step.
Uninstall the application from any user profiles provisioned prior to this.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43303'
  tag rid: 'SV-56056r3_rule'
  tag stig_id: 'WN08-GE-000054'
  tag gtitle: 'WN08-GE-000054'
  tag fix_id: 'F-71667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
