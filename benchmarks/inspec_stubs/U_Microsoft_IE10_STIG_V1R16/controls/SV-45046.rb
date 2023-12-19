control 'SV-45046' do
  title 'Do Not Track header must be sent.'
  desc 'This policy setting allows you to configure how Internet Explorer sends the Do Not Track (DNT) header. If you enable this policy setting, Internet Explorer sends the DNT:1 header on all HTTP and HTTPS requests. The DNT:1 header signals that servers should not track the user. If you disable this policy setting, Internet Explorer sends the DNT:1 header only when a Tracking Protection List is enabled, or when InPrivate Browsing mode is used. If you do not configure this policy setting, users can select the Always send Do Not Track header options on the Advanced tab of the Internet Options dialog box. When this option is selected, Internet Explorer sends the DNT:1 header on all HTTP and HTTPS requests.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page "Always send Do Not Track header" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main

Criteria: If the value DoNotTrack is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page "Always send Do Not Track header" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42425r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34414'
  tag rid: 'SV-45046r1_rule'
  tag stig_id: 'DTBI1040'
  tag gtitle: 'DTBI1040 - Tracking of Headers'
  tag fix_id: 'F-38459r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
