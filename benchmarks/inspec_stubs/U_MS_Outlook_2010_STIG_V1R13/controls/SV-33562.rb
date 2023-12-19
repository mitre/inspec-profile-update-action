control 'SV-33562' do
  title 'Intranet with Safe Zones for automatic picture downloads must be configured.'
  desc "Malicious e-mail senders can send HTML e-mail messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether recipients open the messages. Viewing e-mail messages with Web beacons in them provides confirmation that the recipient's e-mail address is valid, which leaves the recipient vulnerable to additional spam and harmful e-mail.
By default, Outlook does not download external content in HTML e-mail messages from untrusted senders over the local intranet. If this configuration is changed, Outlook will display external content in all HTML e-mail messages received via the local intranet, which could include Web beacons."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Automatic Picture Download Settings “Include Intranet in Safe Zones for Automatic Picture Download” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value Intranet is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Automatic Picture Download Settings “Include Intranet in Safe Zones for Automatic Picture Download” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34021r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17634'
  tag rid: 'SV-33562r2_rule'
  tag stig_id: 'DTOO275 - Outlook'
  tag gtitle: 'DTOO275 - Incl. Intranet with Safe Zone'
  tag fix_id: 'F-29708r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
