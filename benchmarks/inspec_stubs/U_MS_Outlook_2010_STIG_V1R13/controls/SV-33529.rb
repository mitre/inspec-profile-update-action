control 'SV-33529' do
  title 'Automatic download content for email in Safe Senders list must be disallowed.'
  desc "Malicious e-mail senders can send HTML e-mail messages with embedded Web beacons, or pictures and other content from external servers that can be used to track whether specific recipients have opened a message. Viewing an e-mail message that contains a Web beacon provides confirmation that the recipient's e-mail address is valid, which leaves the recipient vulnerable to additional spam and harmful e-mail. To help protect users from Web beacons, Outlook can be configured to automatically block the display of external content in e-mail messages. However, because this configuration could block desirable content from display, Outlook can also be configured to automatically display external content in any messages sent by people who are listed in users' Safe Senders Lists or Safe Recipients Lists.
By default, Outlook automatically displays external content in e-mail messages from people listed in users' Safe Senders Lists or Safe Recipients Lists, and automatically blocks external content in other messages. If a malicious sender is accidentally added to a user's Safe Senders List or Safe Recipients List, Outlook will display external content in all e-mail messages from the malicious sender, which could include Web beacons."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Automatic Picture Download Settings “Automatically download content for e-mail from people in Safe Senders and Safe Recipients Lists” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value UnblockSpecificSenders is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Automatic Picture Download Settings “Automatically download content for e-mail from people in Safe Senders and Safe Recipients Lists” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34013r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17739'
  tag rid: 'SV-33529r1_rule'
  tag stig_id: 'DTOO271 - Outlook'
  tag gtitle: 'DTOO271 - Auto Download from Safe lists'
  tag fix_id: 'F-29701r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
