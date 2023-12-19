control 'SV-77669' do
  title 'The system must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Security.AccountLockFailures value and verify it is set to 3.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures and verify it is set to 3.

If the Security.AccountLockFailures is set to a value other than 3, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Security.AccountLockFailures value and configure it to 3.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63179'
  tag rid: 'SV-77669r1_rule'
  tag stig_id: 'ESXI-06-000005'
  tag gtitle: 'SRG-OS-000021-VMM-000050'
  tag fix_id: 'F-69097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
