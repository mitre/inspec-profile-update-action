control 'SV-40754' do
  title 'Add-on performance notifications must be disallowed.'
  desc "This policy setting prevents Internet Explorer from displaying a notification when the average time it takes to load all the user's enabled add-ons exceeds the threshold.  The notification informs the user that add-ons are slowing their browsing and displays a button which opens the Disable Add-ons dialog box.  The Disable Add-ons dialog box displays the load time for each group of add-ons enabled in the browser.  It allows the user to disable add-ons and configure the threshold. If you enable this policy setting, users will not be notified when the average time it takes to load all the user's enabled add-ons exceeds the threshold."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable add-on performance notifications" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext 

Criteria: If the value DisableAddonLoadTimePerformanceNotifications  is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable add-on performance notifications" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39499r2_chk'
  tag severity: 'medium'
  tag gid: 'V-30774'
  tag rid: 'SV-40754r1_rule'
  tag stig_id: 'DTBI745'
  tag gtitle: 'DTBI745 - Add-On Performance Notifications'
  tag fix_id: 'F-34614r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
