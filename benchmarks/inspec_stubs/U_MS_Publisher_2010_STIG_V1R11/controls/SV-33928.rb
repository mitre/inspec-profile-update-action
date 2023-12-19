control 'SV-33928' do
  title 'Trust Bar Notifications for unsigned application add-ins must be blocked.'
  desc 'If an application is configured to require all add-ins be signed by a trusted publisher, any unsigned add-ins the application loads will be disabled and the application will display the Trust Bar at the top of the active window. The Trust Bar contains a message informing users about the unsigned add-in.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2010 -> Security -> Trust Center “Disable Trust Bar Notification for unsigned application add-ins” must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\publisher\\security

Criteria: If the value NoTBPromptUnsignedAddin is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2010 -> Security -> Trust Center “Disable Trust Bar Notification for unsigned application add-ins” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Publisher 2010'
  tag check_id: 'C-34370r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17187'
  tag rid: 'SV-33928r1_rule'
  tag stig_id: 'DTOO131 - Publisher'
  tag gtitle: 'DTOO131 - Trust Bar Notifications'
  tag fix_id: 'F-30002r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
