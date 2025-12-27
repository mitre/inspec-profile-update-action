control 'SV-33906' do
  title 'ActiveX Installs must be configured for proper restriction.'
  desc 'Microsoft ActiveX controls allow unmanaged, unprotected code to run on the user computers. ActiveX controls do not run within a protected container in the browser like the other types of HTML or Microsoft Silverlight-based controls. Disabling or not configuring this setting does not block prompts for ActiveX control installations and these prompts display to users. This could allow malicious code to become active on user computers or the network.'
  desc 'check', "The policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Restrict ActiveX Install” must be set to “Enabled” and 'onent.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_RESTRICT_ACTIVEXINSTALL

Criteria: If the value onenote.exe is REG_DWORD = 1, this is not a finding."
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Restrict ActiveX Install” to “Enabled” and 'onent.exe' is checked."
  impact 0.5
  ref 'DPMS Target Microsoft OneNote 2010'
  tag check_id: 'C-34335r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26586'
  tag rid: 'SV-33906r2_rule'
  tag stig_id: 'DTOO211 - OneNote'
  tag gtitle: 'DTOO211 - Restrict ActiveX Install'
  tag fix_id: 'F-29981r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
