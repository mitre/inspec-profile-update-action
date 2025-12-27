control 'SV-54048' do
  title 'Internet with Safe Zones for Picture Download must be disabled.'
  desc "Malicious email senders can send HTML email messages with embedded Web beacons, which are pictures and other content from external servers that can be used to track whether recipients open the messages. Viewing email messages that contain Web beacons provides confirmation that the recipient's email address is valid, which leaves the recipient vulnerable to additional spam and harmful email.
By default, Outlook does not download external content in HTML email messages from untrusted senders via the Internet. If this configuration is changed, Outlook will display external content in all HTML email messages received from the Internet, which could include Web beacons."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Include Internet in Safe Zones for Automatic Picture Download" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail

Criteria: If the value Internet is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Include Internet in Safe Zones for Automatic Picture Download" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47986r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17630'
  tag rid: 'SV-54048r1_rule'
  tag stig_id: 'DTOO274'
  tag gtitle: 'DTOO274 - Internet with Safe Zones'
  tag fix_id: 'F-46927r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
