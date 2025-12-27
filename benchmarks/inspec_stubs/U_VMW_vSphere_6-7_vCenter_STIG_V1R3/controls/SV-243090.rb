control 'SV-243090' do
  title 'The vCenter Server must configure the vpxuser password meets length policy.'
  desc 'The vpxuser password default length is 32 characters. Ensure this setting meets site policies; if not, configure to meet password length policies. 

Longer passwords make brute-force password attacks more difficult. The vpxuser password is added by vCenter, meaning no manual intervention is normally required. The vpxuser password length must never be modified to less than the default length of 32 characters.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Verify that "config.vpxd.hostPasswordLength" is set to "32".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength

Verify it is set to "32".

If the "config.vpxd.hostPasswordLength" is set to a value other than "32", this is a finding. 

If the setting does not exist, this is not a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Click "Edit Settings" and configure the "config.vpxd.hostPasswordLength" value to "32".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command if the setting already exists:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength | Set-AdvancedSetting -Value 32'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46365r719511_chk'
  tag severity: 'medium'
  tag gid: 'V-243090'
  tag rid: 'SV-243090r719513_rule'
  tag stig_id: 'VCTR-67-000024'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46322r719512_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
