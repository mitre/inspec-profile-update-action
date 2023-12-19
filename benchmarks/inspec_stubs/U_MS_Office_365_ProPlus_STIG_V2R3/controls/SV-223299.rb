control 'SV-223299' do
  title 'The Information Bar must be enabled in all Office programs.'
  desc "This policy setting controls whether Office 365 ProPlus applications notify users when potentially unsafe features or content are detected, or whether such features or content are silently disabled without notification. The Message Bar in Office 2016 applications is used to identify security issues, such as unsigned macros or potentially unsafe add-ins. When such issues are detected, the application disables the unsafe feature or content and displays the Message Bar at the top of the active window. The Message Bar informs the users about the nature of the security issue and, in some cases, provides the users with an option to enable the potentially unsafe feature or content, which could harm the user's computer. 

If you enable this policy setting, Office 365 ProPlus applications do not display information in the Message Bar about potentially unsafe content that has been detected or has automatically been blocked. 

If you disable this policy setting, Office 365 ProPlus applications display information in the Message Bar about content that has automatically been blocked. 

If you do not configure this policy setting, if an Office 365 ProPlus application detects a security issue, the Message Bar is displayed. However, this configuration can be modified by users in the Trust Center."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Information Bar is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_securityband

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Information Bar to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24972r442116_chk'
  tag severity: 'medium'
  tag gid: 'V-223299'
  tag rid: 'SV-223299r508019_rule'
  tag stig_id: 'O365-CO-000017'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24960r442117_fix'
  tag 'documentable'
  tag legacy: ['SV-108777', 'V-99673']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
