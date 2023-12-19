control 'SV-223290' do
  title 'Trust Bar notifications must be configured to display information in the Message Bar about the content that has been automatically blocked.'
  desc "This policy setting controls whether Office 365 ProPlus applications notify users when potentially unsafe features or content are detected, or whether such features or content are silently disabled without notification. 

The Message Bar in Office 365 ProPlus applications is used to identify security issues, such as unsigned macros or potentially unsafe add-ins. When such issues are detected, the application disables the unsafe feature or content and displays the Message Bar at the top of the active window. The Message Bar informs the users about the nature of the security issue and, in some cases, provides the users with an option to enable the potentially unsafe feature or content, which could harm the user's computer. 

If you enable this policy setting, Office 365 ProPlus applications do not display information in the Message Bar about potentially unsafe content that has been detected or has automatically been blocked."
  desc 'check', 'Verify the policy value for User Configuration >> Microsoft Office 2016 >> Security Settings >> Disable all Trust Bar notifications for security issues is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\trustcenter

If the value for trustbar is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Disable all Trust Bar notifications for security issues" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24963r442089_chk'
  tag severity: 'medium'
  tag gid: 'V-223290'
  tag rid: 'SV-223290r508019_rule'
  tag stig_id: 'O365-CO-000007'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-24951r442090_fix'
  tag 'documentable'
  tag legacy: ['SV-108757', 'V-99653']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
