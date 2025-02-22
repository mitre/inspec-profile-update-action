control 'SV-228428' do
  title 'ActiveX Installs must be configured for proper restriction.'
  desc 'Microsoft ActiveX controls allow unmanaged, unprotected code to run on the user computers. ActiveX controls do not run within a protected container in the browser like the other types of HTML or Microsoft Silverlight-based controls. Disabling or not configuring this setting does not block prompts for ActiveX control installations, and these prompts display to users. This could allow malicious code to become active on user computers or the network.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Restrict ActiveX Install" is set to "Enabled" and 'outlook.exe' is checked.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL

Criteria: If the value outlook.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2016 (Machine) -> Security Settings -> IE Security "Restrict ActiveX Install" to "Enabled" and place a check in the 'outlook.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30661r497606_chk'
  tag severity: 'medium'
  tag gid: 'V-228428'
  tag rid: 'SV-228428r508021_rule'
  tag stig_id: 'DTOO211'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30646r497607_fix'
  tag 'documentable'
  tag legacy: ['SV-85751', 'V-71127']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
