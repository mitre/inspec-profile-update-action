control 'SV-59345' do
  title 'The Download signed ActiveX controls property must be disallowed (Internet zone).'
  desc 'Active X controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. Signed code is better than unsigned code in that it may be easier to determine its author, but it is still potentially harmful, especially when coming from an untrusted zone. This policy setting allows you to manage whether users may download signed ActiveX controls from a page in the zone. If you enable this policy, users can download signed controls without user intervention. If you select Prompt in the drop-down box, users are queried whether to download controls signed by untrusted publishers. Code signed by trusted publishers is silently downloaded. If you disable the policy setting, signed controls cannot be downloaded.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Download signed ActiveX controls' must be 'Enabled', and 'Disable' selected from the drop-down box.  Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1001" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Download signed ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49689r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46481'
  tag rid: 'SV-59345r1_rule'
  tag stig_id: 'DTBI022-IE11'
  tag gtitle: 'DTBI022-IE11-Download signed ActiveX - Internet'
  tag fix_id: 'F-50271r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
