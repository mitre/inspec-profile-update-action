control 'SV-40768' do
  title 'Internet Explorer Processes for notification bars must be enforced (Explorer).'
  desc 'This policy setting allows you to manage whether the Notification bar is displayed for Internet Explorer processes when file or code installs are restricted.  By default, the Notification bar is displayed for Internet Explorer processes.  If you enable this policy setting, the Notification bar will be displayed for Internet Explorer Processes.  If you disable this policy setting, the Notification bar will not be displayed for Internet Explorer processes.  If you do not configure this policy setting, the Notification bar will be displayed for Internet Explorer Processes'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar-> "Internet Explorer Processes" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_SECURITYBAND 

Criteria: If the value explorer.exe is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar-> "Internet Explorer Processes" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39513r2_chk'
  tag severity: 'medium'
  tag gid: 'V-30780'
  tag rid: 'SV-40768r1_rule'
  tag stig_id: 'DTBI825'
  tag gtitle: 'DTBI825 - Notification Bar Processes - Explorer'
  tag fix_id: 'F-34629r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
