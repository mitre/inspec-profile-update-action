control 'SV-85565' do
  title 'Trust Bar Notifications for unsigned application add-ins must be blocked.'
  desc 'This policy setting controls whether the specified Office application notifies users when unsigned application add-ins are loaded or silently disable such add-ins without notification. This policy setting only applies if you enable the "Require that application add-ins are signed by Trusted Publisher" policy setting, which prevents users from changing this policy setting. If you enable this policy setting, applications automatically disable unsigned add-ins without informing users. If you disable this policy setting, if this application is configured to require that all add-ins be signed by a trusted publisher, any unsigned add-ins the application loads will be disabled and the application will display the Trust Bar at the top of the active window. The Trust Bar contains a message that informs users about the unsigned add-in. If you do not configure this policy setting, the disable behavior applies, and in addition, users can configure this requirement themselves in the "Add-ins" category of the Trust Center for the application.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Application Settings -> Security -> Trust Center "Disable Trust Bar Notification for unsigned application add-ins and block them" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\access\\security

Criteria: If the value NoTBPromptUnsignedAddin is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Application Settings -> Security -> Trust Center "Disable Trust Bar Notification for unsigned application add-ins and block them" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2016'
  tag check_id: 'C-71369r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70941'
  tag rid: 'SV-85565r1_rule'
  tag stig_id: 'DTOO131'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-77273r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
