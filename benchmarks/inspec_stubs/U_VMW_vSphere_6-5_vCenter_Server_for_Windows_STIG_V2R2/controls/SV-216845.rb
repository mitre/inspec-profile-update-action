control 'SV-216845' do
  title 'The vCenter Server for Windows must configure the vpxuser auto-password to be changed every 30 days.'
  desc 'By default, the vpxuser password will be automatically changed by vCenter every 30 days. Ensure this setting meets your policies; if not, configure to meet password aging policies. 

Note: It is very important the password aging policy not be shorter than the default interval that is set to automatically change the vpxuser password, to preclude the possibility that vCenter might get locked out of an ESXi host.'
  desc 'check', 'Select the vCenter Server in the vSphere Web Client object hierarchy.
Click Configure.
Click Advanced Settings and enter VimPasswordExpirationInDays in the filter box.
Verify "VirtualCenter.VimPasswordExpirationInDays" is set to "30".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays and verify it is set to 30.

If the "VirtualCenter.VimPasswordExpirationInDays" is set to a value other than "30" or does not exist, this is a finding.'
  desc 'fix', 'Select the vCenter Server in the vSphere Web Client object hierarchy.
Click Configure.
Click Advanced Settings and enter VimPasswordExpirationInDays in the filter box.
Set "VirtualCenter.VimPasswordExpirationInDays" to "30".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If the setting already exists:
Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays | Set-AdvancedSetting -Value 30

If the setting does not exist:
New-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays -Value 30'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18076r531360_chk'
  tag severity: 'medium'
  tag gid: 'V-216845'
  tag rid: 'SV-216845r612237_rule'
  tag stig_id: 'VCWN-65-000023'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18074r531361_fix'
  tag 'documentable'
  tag legacy: ['SV-104587', 'V-94757']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
