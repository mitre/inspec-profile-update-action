control 'SV-45233' do
  title 'Internet Explorer Processes for Notification Bars must be enforced (Reserved).'
  desc 'This policy setting allows you to manage whether the Notification bar is displayed for Internet Explorer processes when file or code installs are restricted. By default, the Notification Bar is displayed for Internet Explorer processes. If you enable this policy setting, the Notification bar will be displayed for Internet Explorer processes. If you disable this policy setting, the Notification bar will not be displayed for Internet Explorer processes. If you do not configure this policy setting, the Notification bar will be displayed for Internet Explorer processes.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar-> "Internet Explorer Processes" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND 

Criteria: If the value (Reserved) is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar-> "Internet Explorer Processes" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-30779'
  tag rid: 'SV-45233r1_rule'
  tag stig_id: 'DTBI815'
  tag gtitle: 'DTBI815 - Notification Bar Process - Reserved'
  tag fix_id: 'F-38629r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
