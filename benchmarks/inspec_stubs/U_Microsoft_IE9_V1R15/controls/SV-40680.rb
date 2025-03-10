control 'SV-40680' do
  title 'The URL to be displayed for checking updates to Internet Explorer and Internet Tools must be about:blank.'
  desc 'This policy setting allows checking for updates for Internet Explorer from the specified URL, included by default in Internet Explorer. If you enable this policy setting, users will not be able to change the URL to be displayed for checking updates to Internet Explorer and Internet Tools. The URL must be specified to be displayed for checking updates to Internet Explorer and Internet Tools. If you disable or do not configure this policy setting, users will be able to change the URL to be displayed for checking updates to Internet Explorer and Internet Tools.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Settings -> Component Updates -> Periodic check for updates to Internet Explorer and Internet Tools -> "Turn off changing the URL to be displayed for checking updates to Internet Explorer and Internet Tools" must be “Enabled” with a "blank or empty" selection box. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: The Update_Check_Page value must exist. The value must contain no data value. If the value Update_Check_Page is not present, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Settings -> Component Updates -> Periodic check for updates to Internet Explorer and Internet Tools -> "Turn off changing the URL to be displayed for checking updates to Internet Explorer and Internet Tools" to “Enabled” with a "blank or empty" selection box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39410r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15563'
  tag rid: 'SV-40680r1_rule'
  tag stig_id: 'DTBI675'
  tag gtitle: "DTBI675 - Displaying URL's for update checking"
  tag fix_id: 'F-34534r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
