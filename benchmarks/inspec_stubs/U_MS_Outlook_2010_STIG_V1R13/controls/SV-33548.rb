control 'SV-33548' do
  title 'External content and pictures in HTML eMail must be displayed.'
  desc "Malicious email senders can send HTML email messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether specific recipients open the message. Viewing an email message that contains a Web beacon provides confirmation that the recipient's email address is valid, which leaves the recipient vulnerable to additional spam and harmful email.
By default, Outlook does not download external content in HTML email and RSS items unless the content is considered safe. Content that Outlook can be configured to consider safe includes:
• Content in email messages from senders and to recipients defined in the Safe Senders and Safe Recipients lists. 
• Content from Web sites in Internet Explorer's Trusted Sites security zone. 
• Content in RSS items.
• Content from SharePoint Discussion Boards.
Users can control what content is considered safe by changing the options in the Automatic Download section of the Trust Center. If Outlook's default blocking configuration is overridden, in the Trust Center or by some other method, Outlook will display external content in all HTML email messages, including any that include Web beacons."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office Outlook 2010 >> Security >> Automatic Picture Download Settings “Display pictures and external content in HTML e-mail” is set to “Enable”.

NOTE: When this setting is Enabled, Outlook 2010 blocks automatic download of content from external servers unless the sender is included in the Safe Senders list. Recipients can choose to download external content from untrusted senders on a message-by-message basis.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Outlook\\Options\\Mail

Criteria: If the value BlockExtContent is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2010 >> Security >> Automatic Picture Download Settings “Display pictures and external content in HTML e-mail” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34015r5_chk'
  tag severity: 'medium'
  tag gid: 'V-17672'
  tag rid: 'SV-33548r2_rule'
  tag stig_id: 'DTOO270 - Outlook'
  tag gtitle: 'DTOO270 - External Pictures & content'
  tag fix_id: 'F-29703r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
