control 'SV-33604' do
  title 'Trust Bar Notifications for unsigned application add-ins must be blocked.'
  desc 'If an application is configured to require all add-ins be signed by a trusted publisher, any unsigned add-ins the application loads will be disabled and the application will display the Trust Bar at the top of the active window. The Trust Bar contains a message informing users about the unsigned add-in.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security -> Trust Center “Disable Trust Bar Notification for unsigned application add-ins and block them” must be “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\security

Criteria: If the value NoTBPromptUnsignedAddin is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security -> Trust Center “Disable Trust Bar Notification for unsigned application add-ins and block them” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34069r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17187'
  tag rid: 'SV-33604r1_rule'
  tag stig_id: 'DTOO131 - PowerPoint'
  tag gtitle: 'DTOO131 - Trust Bar Notifications'
  tag fix_id: 'F-29746r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
