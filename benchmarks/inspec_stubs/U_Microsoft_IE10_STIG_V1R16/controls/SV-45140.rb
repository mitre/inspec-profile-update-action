control 'SV-45140' do
  title 'Displaying of the reveal password button must be disallowed.'
  desc 'This policy setting allows you to hide the reveal password button when Internet Explorer prompts users for a password. The reveal password button is displayed during password entry. When the user clicks the button, the current password value is visible until the mouse button is released (or until the tap ends). If you enable this policy setting, the reveal password button will be hidden for all password fields. Users and developers will not be able to depend on the reveal password button being displayed in any web form or web application. If you disable or do not configure this policy setting, the reveal password button can be shown by the application as a user types in a password. *Note: On at least Windows 8, if the "Do not display the reveal password button" policy setting located in Computer Configuration\\Administrative Templates\\Windows Components\\Credential User Interface is enabled for the system, it will override this policy setting.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Security Features "Do not display the reveal password button" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value DisablePasswordReveal is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Security Features "Do not display the reveal password button" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42483r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34456'
  tag rid: 'SV-45140r1_rule'
  tag stig_id: 'DTBI1035'
  tag gtitle: 'DTBI1035 - Displaying of the reveal password button'
  tag fix_id: 'F-38536r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
