control 'SV-78473' do
  title 'The system must ensure the vpxuser auto-password change meets policy.'
  desc 'By default, the vpxuser password will be automatically changed by vCenter every 30 days. Ensure this setting meets your policies; if not, configure to meet password aging policies. 

Note: It is very important the password aging policy not be shorter than the default interval that is set to automatically change the vpxuser password, to preclude the possibility that vCenter might get locked out of an ESXi host.'
  desc 'check', 'From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings.  Verify that VirtualCenter.VimPasswordExpirationInDays is set to 30.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays and verify it is set to 30.

If the VirtualCenter.VimPasswordExpirationInDays is set to a value other than 30 or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings.  Click Edit and edit the VirtualCenter.VimPasswordExpirationInDays setting to 30 or if the value does not exist create it by entering the values in the Key and Value fields and clicking Add.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If the setting already exists:

Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays | Set-AdvancedSetting -Value 30

If the setting does not exist:

New-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays -Value 30'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63983'
  tag rid: 'SV-78473r1_rule'
  tag stig_id: 'VCWN-06-000023'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69913r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
