control 'SV-85323' do
  title 'ActiveX Installs must be configured for proper restriction in PowerPoint Viewer.'
  desc 'Microsoft ActiveX controls allow unmanaged, unprotected code to run on the user computers. ActiveX controls do not run within a protected container in the browser like the other types of HTML or Microsoft Silverlight-based controls. Disabling or not configuring this setting does not block prompts for ActiveX control installations, and these prompts display to users. This could allow malicious code to become active on user computers or the network.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Restrict ActiveX Install" is set to "Enabled" and 'pptview.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL

Criteria: If the value pptview.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Restrict ActiveX Install" to "Enabled" and place a check in the 'pptview.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71181r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70699'
  tag rid: 'SV-85323r1_rule'
  tag stig_id: 'DTOO510'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-77023r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
