control 'SV-45241' do
  title 'Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved).'
  desc "Internet Explorer allows scripts to programmatically open, resize, and reposition various types of windows. Often, disreputable websites will resize windows to either hide other windows or force the user to interact with a window containing malicious code. The Scripted Window Security Restrictions security feature restricts pop-up windows and prohibits scripts from displaying windows in which the title and status bars are not visible to the user, or which hide other windows' title and status bars. If you enable the Scripted Window Security Restrictions\\Internet Explorer Processes policy setting, pop-up windows and other restrictions apply for Windows Explorer and Internet Explorer processes. If you disable or do not configure this policy setting, scripts can continue to create pop-up windows, and windows that hide other windows. Recommend configuring this setting to Enabled to help prevent malicious websites from controlling the Internet Explorer windows or fooling users into clicking on the wrong window."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions -> "Internet Explorer Processes" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS 

Criteria: If the value (Reserved) is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions -> "Internet Explorer Processes" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42590r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15559'
  tag rid: 'SV-45241r1_rule'
  tag stig_id: 'DTBI645'
  tag gtitle: 'DTBI645 - Restricting Pop Up Windows - Reserved'
  tag fix_id: 'F-38637r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
