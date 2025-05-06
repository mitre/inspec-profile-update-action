control 'SV-33597' do
  title 'Hyperlinks in suspected phishing e-mail messages must be disallowed.'
  desc "Outlook's Junk E-mail Filter evaluates each incoming message for possible spam or phishing content. Suspicious message detection is always turned on.  By default, Outlook handles suspicious messages in two ways:
•	If the Junk E-mail Filter does not consider a message to be spam but does consider it to be phishing, the message is left in the Inbox but any links in the message are disabled and users cannot use the Reply and Reply All functionality. In addition, any attachments in the suspicious message are blocked. 
•	If the Junk E-mail Filter considers the message to be both spam and phishing, the message is automatically sent to the Junk E-mail folder. Any message sent to the Junk E-mail folder is converted to plain text format and all links are disabled. In addition, the Reply and Reply All functionality is disabled and any attachments in the message are blocked. The InfoBar alerts users to this change in functionality. If users are certain that a message is legitimate, they can click the InfoBar and enable the links in the message.
Users can change the way Outlook handles phishing messages in the Junk E-mail Options dialog box by clearing the Disable links and other functionality in phishing messages (Recommended) check box. If this check box is cleared, Outlook will not disable links in suspected phishing messages unless they are classified as junk e-mail, which could allow users to disclose confidential information to malicious Web sites."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Trust Center “Allow hyperlinks in suspected phishing e-mail messages” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value JunkMailEnableLinks is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Trust Center “Allow hyperlinks in suspected phishing e-mail messages” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17613'
  tag rid: 'SV-33597r1_rule'
  tag stig_id: 'DTOO277 - Outlook'
  tag gtitle: 'DTOO277 - Links in Email Messages'
  tag fix_id: 'F-29739r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
