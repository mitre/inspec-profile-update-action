control 'SV-258728' do
  title 'The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Once the configured number of attempts is reached, the account is locked by the ESXi host.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Security.AccountLockFailures" value and verify it is set to "3".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures

If the "Security.AccountLockFailures" setting is set to a value other than "3", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Security.AccountLockFailures" value and configure it to "3".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62468r933243_chk'
  tag severity: 'medium'
  tag gid: 'V-258728'
  tag rid: 'SV-258728r933245_rule'
  tag stig_id: 'ESXI-80-000005'
  tag gtitle: 'SRG-OS-000021-VMM-000050'
  tag fix_id: 'F-62377r933244_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
