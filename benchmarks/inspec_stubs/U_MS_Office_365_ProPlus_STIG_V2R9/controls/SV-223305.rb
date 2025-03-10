control 'SV-223305' do
  title 'ActiveX installation restriction must be enabled in all Office programs.'
  desc 'Microsoft ActiveX controls allow unmanaged, unprotected code to run on the user computers. ActiveX controls do not run within a protected container in the browser like the other types of HTML or Microsoft Silverlight-based controls. Disabling or not configuring this setting does not block prompts for ActiveX control installations, and these prompts display to users. This could allow malicious code to become active on user computers or the network.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Restrict ActiveX Install is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_restrict_activexinstall

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Restrict ActiveX Install to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24978r442134_chk'
  tag severity: 'medium'
  tag gid: 'V-223305'
  tag rid: 'SV-223305r879859_rule'
  tag stig_id: 'O365-CO-000023'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-24966r442135_fix'
  tag 'documentable'
  tag legacy: ['SV-108789', 'V-99685']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
