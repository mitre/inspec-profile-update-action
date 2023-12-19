control 'SV-40628' do
  title 'Third-party browser extensions must be disallowed.'
  desc "This policy setting allows you to manage whether Internet Explorer will launch COM add-ons, known as browser helper objects such as toolbars. Browser helper objects may contain flaws such as buffer overruns which impact Internet Explorer's performance or stability. If you enable this policy setting, Internet Explorer automatically launches any browser helper objects that are installed on the user's computer. If you disable this policy setting, browser helper objects do not launch. If you do not configure this policy, Internet Explorer automatically launches any browser helper objects that are installed on the user's computer."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> "Allow third-party browser extensions" must be “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value Enable Browser Extensions is REG_SZ = no, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> "Allow third-party browser extensions" to “Disabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39367r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15500'
  tag rid: 'SV-40628r2_rule'
  tag stig_id: 'DTBI355'
  tag gtitle: 'DTBI355 - Third-party browser extensions'
  tag fix_id: 'F-34481r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
