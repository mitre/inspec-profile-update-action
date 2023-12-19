control 'SV-45214' do
  title 'InPrivate Browsing must be disallowed.'
  desc 'InPrivate Browsing lets the user control whether or not Internet Explorer saves the browsing history, cookies, and other data. User control of settings is not the preferred control method. The InPrivate Browsing feature in Internet Explorer makes browser privacy easy by not storing history, cookies, temporary Internet files, or other data. If you enable this policy setting, InPrivate Browsing will be disabled. If you disable this policy setting, InPrivate Browsing will be available for use. If you do not configure this setting, InPrivate Browsing can be turned on or off through the registry.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Privacy -> "Turn off InPrivate Browsing" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Privacy 

Criteria: If the value EnableInPrivateBrowsing is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Privacy -> "Turn off InPrivate Browsing" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42562r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22150'
  tag rid: 'SV-45214r1_rule'
  tag stig_id: 'DTBI780'
  tag gtitle: 'DTBI780 - InPrivate Browsing'
  tag fix_id: 'F-38610r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
