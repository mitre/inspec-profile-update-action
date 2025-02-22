control 'SV-207607' do
  title 'The ESXi host must enforce the unlock timeout of 15 minutes after a user account is locked out.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings.  Select the Security.AccountUnlockTime value and verify it is set to 900.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime and verify it is set to 900.

If the Security.AccountUnlockTime is set to a value other than 900, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the Security.AccountUnlockTime value and configure it to 900.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7862r364220_chk'
  tag severity: 'medium'
  tag gid: 'V-207607'
  tag rid: 'SV-207607r379606_rule'
  tag stig_id: 'ESXI-65-000006'
  tag gtitle: 'SRG-OS-000329-VMM-001180'
  tag fix_id: 'F-7862r364221_fix'
  tag 'documentable'
  tag legacy: ['V-93959', 'SV-104045']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
