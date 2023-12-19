control 'SV-243089' do
  title 'The vCenter Server must configure the vpxuser auto-password to be changed every 30 days.'
  desc 'By default, the vpxuser password will be automatically changed by vCenter every 30 days. Ensure this setting meets site policies; if not, configure to meet password aging policies. 

Note: It is very important the password aging policy not be shorter than the default interval that is set to automatically change the vpxuser password, to preclude the possibility that vCenter might be locked out of an ESXi host.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Verify that "VirtualCenter.VimPasswordExpirationInDays" is set to "30".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays and verify it is set to 30.

If the "VirtualCenter.VimPasswordExpirationInDays" is set to a value other than "30" or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Click "Edit Settings" and configure the "VirtualCenter.VimPasswordExpirationInDays" value to "30".

If the value does not exist, create it by entering the values in the "Key" and "Value" fields and clicking "Add".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

If the setting already exists:
Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays | Set-AdvancedSetting -Value 30

If the setting does not exist:
New-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays -Value 30'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46364r719508_chk'
  tag severity: 'medium'
  tag gid: 'V-243089'
  tag rid: 'SV-243089r879887_rule'
  tag stig_id: 'VCTR-67-000023'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46321r719509_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
