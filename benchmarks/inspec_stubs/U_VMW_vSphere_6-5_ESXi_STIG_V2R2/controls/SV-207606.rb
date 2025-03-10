control 'SV-207606' do
  title 'The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings.  Select the Security.AccountLockFailures value and verify it is set to 3.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures and verify it is set to 3.

If the Security.AccountLockFailures is set to a value other than 3, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the Security.AccountLockFailures value and configure it to 3.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7861r364217_chk'
  tag severity: 'medium'
  tag gid: 'V-207606'
  tag rid: 'SV-207606r378517_rule'
  tag stig_id: 'ESXI-65-000005'
  tag gtitle: 'SRG-OS-000021-VMM-000050'
  tag fix_id: 'F-7861r364218_fix'
  tag 'documentable'
  tag legacy: ['V-93957', 'SV-104043']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
