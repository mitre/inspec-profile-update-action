control 'SV-53228' do
  title 'Trust Bar Notifications for unsigned application add-ins must be blocked.'
  desc "If an application is configured to require all add-ins to be signed by a trusted publisher, any unsigned add-ins the application loads will be disabled and the application will display the Trust Bar at the top of the active window. The Trust Bar contains a message informing users about the unsigned add-in. If a user is allowed to make the determination to allow an unsigned add-in, it increases the risk of malicious code being introduced onto the user's computer or the network."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2013 -> Project Options -> Security -> Trust Center -> "Disable Trust Bar Notification for unsigned application add-ins and block them" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\ms project\\security

Criteria: If the value notbpromptunsignedaddin is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2013 -> Project Options -> Security -> Trust Center -> "Disable Trust Bar Notification for unsigned application add-ins and block them" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Project 2013'
  tag check_id: 'C-47535r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40889'
  tag rid: 'SV-53228r1_rule'
  tag stig_id: 'DTOO131'
  tag gtitle: 'DTOO131 - Trust Bar Notifications'
  tag fix_id: 'F-46155r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
