control 'SV-54042' do
  title 'External content and pictures in HTML email must be displayed.'
  desc "Malicious email senders can send HTML email messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether specific recipients open the message. Viewing an email message that contains a Web beacon provides confirmation that the recipient's email address is valid, which leaves the recipient vulnerable to additional spam and harmful email. 

By default, Outlook does not download external content in HTML email and RSS items unless the content is considered safe. Content that Outlook can be configured to consider safe includes: 

* Content in email messages from senders and to recipients defined in the Safe Senders and Safe Recipients lists. 
* Content from websites in Internet Explorer's Trusted Sites security zone. 
* Content in RSS items.
* Content from SharePoint Discussion Boards. 

Users can control what content is considered safe by changing the options in the Automatic Download section of the Trust Center. If Outlook's default blocking configuration is overridden, in the Trust Center or by some other method, Outlook will display external content in all HTML email messages, including any that include Web beacons."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Automatic Picture Download Settings "Display pictures and external content in HTML e-mail" is set to "Enabled".

NOTE: When this setting is Enabled, Outlook 2007 does block automatic download of content from external servers unless the sender is included in the Safe Senders list. Recipients can choose to download external content from untrusted senders on a message-by-message basis.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail

Criteria: If the value BlockExtContent is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Display pictures and external content in HTML e-mail" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47982r6_chk'
  tag severity: 'medium'
  tag gid: 'V-17672'
  tag rid: 'SV-54042r3_rule'
  tag stig_id: 'DTOO270'
  tag gtitle: 'DTOO270 - External Pictures & content'
  tag fix_id: 'F-46922r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
