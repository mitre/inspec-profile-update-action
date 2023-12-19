control 'SV-216846' do
  title 'The vCenter Server for Windows must configure the vpxuser password meets length policy.'
  desc 'The vpxuser password default length is 32 characters. Ensure this setting meets site policies; if not, configure to meet password length policies. Longer passwords make brute-force password attacks more difficult. The vpxuser password is added by vCenter, meaning no manual intervention is normally required. The vpxuser password length must never be modified to less than the default length of 32 characters.'
  desc 'check', 'From the vSphere Web Client go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Verify that "config.vpxd.hostPasswordLength" is set to "32".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength and verify it is set to 32.

If the "config.vpxd.hostPasswordLength" is set to a value other than "32" or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings. Click "Edit" and edit the "config.vpxd.hostPasswordLength" value to "32" or if the value does not exist create it by entering the values in the "Key" and "Value" fields and clicking "Add".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If the setting already exists:
Get-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength | Set-AdvancedSetting -Value 32

If the setting does not exist:
New-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength -Value 32'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18077r366252_chk'
  tag severity: 'medium'
  tag gid: 'V-216846'
  tag rid: 'SV-216846r879887_rule'
  tag stig_id: 'VCWN-65-000024'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18075r366253_fix'
  tag 'documentable'
  tag legacy: ['SV-104589', 'V-94759']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
