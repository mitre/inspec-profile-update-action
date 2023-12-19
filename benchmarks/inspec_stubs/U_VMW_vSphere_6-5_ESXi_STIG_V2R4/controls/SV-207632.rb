control 'SV-207632' do
  title 'The ESXi host  must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Select the Security.PasswordQualityControl value and verify it is set to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

If the Security.PasswordQualityControl setting is not set to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15", this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the Security.PasswordQualityControl value and configure it to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15".

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7887r364295_chk'
  tag severity: 'medium'
  tag gid: 'V-207632'
  tag rid: 'SV-207632r378739_rule'
  tag stig_id: 'ESXI-65-000031'
  tag gtitle: 'SRG-OS-000069-VMM-000360'
  tag fix_id: 'F-7887r364296_fix'
  tag 'documentable'
  tag legacy: ['V-94009', 'SV-104095']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
