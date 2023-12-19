control 'SV-78021' do
  title 'The VMM must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Security.PasswordQualityControl value and verify it is set to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

If the Security.PasswordQualityControl setting is not set to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15", this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Security.PasswordQualityControl value and configure it to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15".

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64281r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63531'
  tag rid: 'SV-78021r1_rule'
  tag stig_id: 'ESXI-06-100031'
  tag gtitle: 'SRG-OS-000070-VMM-000370'
  tag fix_id: 'F-69461r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
