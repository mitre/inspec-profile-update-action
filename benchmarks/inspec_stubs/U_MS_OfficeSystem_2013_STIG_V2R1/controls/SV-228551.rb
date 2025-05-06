control 'SV-228551' do
  title 'Trust Bar notifications for Security messages must be enforced.'
  desc "The Message Bar in Office applications is used to identify security issues, such as unsigned macros or potentially unsafe add-ins. When such issues are detected, the application disables the unsafe feature or content and displays the Message Bar at the top of the active window. The Message Bar informs the users about the nature of the security issue and, in some cases, provides the users with an option to enable the potentially unsafe feature or content, which could harm the user's computer.
By default, if an Office application detects a security issue, the Message Bar is displayed. However, this configuration can be modified by users in the Trust Center."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Disable all Trust Bar notifications for security issues" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\trustcenter

If the value 'TrustBar' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Disable all Trust Bar notifications for security issues" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30784r498931_chk'
  tag severity: 'medium'
  tag gid: 'V-228551'
  tag rid: 'SV-228551r508020_rule'
  tag stig_id: 'DTOO186'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-30769r498932_fix'
  tag 'documentable'
  tag legacy: ['V-17590', 'SV-52723']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
