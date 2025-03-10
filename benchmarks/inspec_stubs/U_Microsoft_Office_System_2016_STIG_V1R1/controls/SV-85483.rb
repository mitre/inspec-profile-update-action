control 'SV-85483' do
  title 'Trust Bar notifications for Security messages must be enforced.'
  desc "This policy setting controls whether Office 2016 applications notify users when potentially unsafe features or content are detected, or whether such features or content are silently disabled without notification. The Message Bar in Office 2016 applications is used to identify security issues, such as unsigned macros or potentially unsafe add-ins. When such issues are detected, the application disables the unsafe feature or content and displays the Message Bar at the top of the active window. The Message Bar informs the users about the nature of the security issue and, in some cases, provides the users with an option to enable the potentially unsafe feature or content, which could harm the user's computer. If you enable this policy setting, Office 2016 applications do not display information in the Message Bar about potentially unsafe content that has been detected or has automatically been blocked. If you disable this policy setting, Office 2016 applications display information in the Message Bar about content that has automatically been blocked. If you do not configure this policy setting, if an Office 2016 application detects a security issue, the Message Bar is displayed. However, this configuration can be modified by users in the Trust Center."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Disable all Trust Bar notifications for security issues" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\trustcenter

Criteria: If the value TrustBar is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Disable all Trust Bar notifications for security issues" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71303r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70859'
  tag rid: 'SV-85483r1_rule'
  tag stig_id: 'DTOO186'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
