control 'SV-45435' do
  title 'The update check interval must be configured and set to 30 days.'
  desc 'Although Microsoft thoroughly tests all patches and service packs before they are published, organizations should carefully control all of the software that is installed on their managed computers. This setting specifies the update check interval, automatic installation, and the default interval value, which is 30 days. If you enable this policy setting, the user will not be able to configure the update check interval, and computers will not automatically download and install updates for Internet Explorer. The update check interval must be specified. If you disable or do not configure this policy setting, the user will have the freedom to configure the update check interval.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Settings -> Component Updates -> Periodic check for updates to Internet Explorer and Internet Tools -> "Prevent specifying the update check interval (in days)" must be "Enabled", and "30" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value Update_Check_Interval is REG_DWORD = 30 (Decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Settings -> Component Updates -> Periodic check for updates to Internet Explorer and Internet Tools -> "Prevent specifying the update check interval (in days)" to "Enabled", and select "30" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42784r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15564'
  tag rid: 'SV-45435r1_rule'
  tag stig_id: 'DTBI680'
  tag gtitle: 'DTBI680 - Update check interval'
  tag fix_id: 'F-38832r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
