control 'SV-48387' do
  title 'The Windows 8 Games app must be removed from the system.'
  desc 'Some Windows 8 default apps provide links to external services and must be removed from the system.'
  desc 'check', 'Verify the Games app has been removed from the system.
Open a command prompt as an administrator.
Enter "dism /online /Get-ProvisionedAppxPackages".
If "DisplayName : Microsoft.XboxLIVEGames" is listed, this is a finding.'
  desc 'fix', 'Remove the Games app from the system.
Open a command prompt as an administrator.
Enter "dism /online /Get-ProvisionedAppxPackages".
Make note of the PackageName (e.g., Microsoft.XboxLIVEGames_1.0.927.0_x64__8wekyb3d8bbwe)
Enter the following to remove the app package from the system: "dism /online /Remove-ProvisionedAppxPackage /PackageName:packagename" substituting "packagename" noted from the previous step.
Uninstall the application from any user profiles provisioned prior to this.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45056r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36738'
  tag rid: 'SV-48387r2_rule'
  tag stig_id: 'WN08-GE-000033'
  tag gtitle: 'WN08-GE-000033'
  tag fix_id: 'F-41518r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
