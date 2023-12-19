control 'SV-40706' do
  title 'Updates to web site lists from Microsoft must be disallowed.'
  desc 'This policy controls the web site compatibility lists provided by Microsoft. If you enable this policy setting, the compatibility web site lists provided by Microsoft will be used during browser navigation. If a user visits a site on the compatibility list provided by Microsoft, the page will automatically display in Compatibility view. If you disable this policy setting, the Microsoft web site list will not be used. Additionally, users can not enable the feature using the Compatibility View Settings dialog box. If you do not configure this setting, the Microsoft web site list will not be active. The user can enable the functionality using the Compatibility View Settings dialog box.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Compatibility View -> “Include updated Web site lists from Microsoft” must be “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\BrowserEmulation 

Criteria: If the value MSCompatibilityMode is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Compatibility View -> “Include updated Web site lists from Microsoft” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39433r3_chk'
  tag severity: 'low'
  tag gid: 'V-22147'
  tag rid: 'SV-40706r1_rule'
  tag stig_id: 'DTBI750'
  tag gtitle: 'DTBI750 - Microsoft web site list updates'
  tag fix_id: 'F-34562r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
