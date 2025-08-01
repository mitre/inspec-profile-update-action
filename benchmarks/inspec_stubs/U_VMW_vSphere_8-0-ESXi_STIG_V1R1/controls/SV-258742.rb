control 'SV-258742' do
  title 'The ESXi host must enforce an unlock timeout of 15 minutes after a user account is locked out.'
  desc 'By enforcing a reasonable unlock timeout after multiple failed logon attempts, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Users must wait for the timeout period to elapse before subsequent logon attempts are allowed.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Security.AccountUnlockTime" value and verify it is set to less than "900" and not "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime

If the "Security.AccountUnlockTime" setting is less than 900 or 0, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Security.AccountUnlockTime" value and configure it to "900".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62482r933285_chk'
  tag severity: 'medium'
  tag gid: 'V-258742'
  tag rid: 'SV-258742r933287_rule'
  tag stig_id: 'ESXI-80-000111'
  tag gtitle: 'SRG-OS-000329-VMM-001180'
  tag fix_id: 'F-62391r933286_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
