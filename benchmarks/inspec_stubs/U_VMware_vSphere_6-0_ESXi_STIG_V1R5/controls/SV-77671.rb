control 'SV-77671' do
  title 'The system must enforce the unlock timeout of 15 minutes after a user account is locked out.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Security.AccountUnlockTime value and verify it is set to 900.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime and verify it is set to 900.

If the Security.AccountUnlockTime is set to a value other than 900, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Security.AccountUnlockTime value and configure it to 900.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63181'
  tag rid: 'SV-77671r1_rule'
  tag stig_id: 'ESXI-06-000006'
  tag gtitle: 'SRG-OS-000329-VMM-001180'
  tag fix_id: 'F-69099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
