control 'SV-54047' do
  title 'IE Trusted Zones assumed trusted must be blocked.'
  desc %q(Malicious users can send HTML email messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether specific recipients open the message. Viewing an email message that contains a Web beacon provides confirmation that the recipient's email address is valid, which leaves the recipient vulnerable to additional spam and harmful email.
To reduce the risk from Web beacons, Outlook disables external content in email messages by default, unless the content is considered "safe" as determined by the check boxes in the Automatic Download section of the Trust Center. Depending on how these options are configured, safe content can include content in messages from addresses defined in the Safe Senders and Safe Recipients Lists used by the Junk email filter, content from SharePoint discussion boards, and content from websites in the Trusted sites zone in Internet Explorer.
By default, Outlook considers trusted sites from Internet Explorer safe, and automatically downloads content from them, which could potentially include Web beacons.)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Block Trusted Zones" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail

Criteria: If the value TrustedZone is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Block Trusted Zones" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17564'
  tag rid: 'SV-54047r1_rule'
  tag stig_id: 'DTOO273'
  tag gtitle: 'DTOO273 - Block Trusted Zones'
  tag fix_id: 'F-46926r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
