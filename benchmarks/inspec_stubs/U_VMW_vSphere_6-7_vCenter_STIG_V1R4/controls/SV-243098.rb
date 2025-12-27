control 'SV-243098' do
  title 'The vCenter Server must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Verify that "config.log.level" value is set to "info".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level 

Verify it is set to "info".

If the "config.log.level" value is not set to "info" or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> Settings >> Advanced Settings. 

Click "Edit Settings" and configure the "config.log.level" setting to "info".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level | Set-AdvancedSetting -Value info'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46373r719535_chk'
  tag severity: 'medium'
  tag gid: 'V-243098'
  tag rid: 'SV-243098r879845_rule'
  tag stig_id: 'VCTR-67-000036'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-46330r719536_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
