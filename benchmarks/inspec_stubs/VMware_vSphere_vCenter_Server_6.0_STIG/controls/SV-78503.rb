control 'SV-78503' do
  title 'The system must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings.  Verify that config.log.level is set to "info".

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level and verify it is set to "info".

If the config.log.level is set to a value other than info or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings.  Click Edit and edit the config.log.level setting to info or if the value does not exist create it by entering the values in the Key and Value fields and clicking Add.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If the setting already exists:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level | Set-AdvancedSetting -Value info

If the setting does not exist:

New-AdvancedSetting -Entity <vcenter server name> -Name config.log.level -Value info'
  impact 0.3
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64765r1_chk'
  tag severity: 'low'
  tag gid: 'V-64013'
  tag rid: 'SV-78503r1_rule'
  tag stig_id: 'VCWN-06-000036'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-69943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
