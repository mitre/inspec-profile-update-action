control 'SV-223354' do
  title 'Internet must not be included in Safe Zone for picture download in Outlook.'
  desc 'This policy setting controls whether pictures and external content in HTML e-mail messages from untrusted senders on the Internet are downloaded without Outlook users explicitly choosing to do so. 

If you enable this policy setting, Outlook will automatically download external content in all e-mail messages sent over the Internet and users will not be able to change the setting. 

If you disable or do not configure this policy setting, Outlook does not consider the Internet a safe zone, which means that Outlook will not automatically download content from external servers unless the sender is included in the Safe Senders list. Recipients can choose to download external content from untrusted senders on a message-by-message basis.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Automatic Picture Download Settings >> Include Internet in Safe Zones for Automatic Picture Download is set to "Disabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\options\\mail

If the value for Internet is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Automatic Picture Download Settings >> Include Internet in Safe Zones for Automatic Picture Download to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25027r836315_chk'
  tag severity: 'medium'
  tag gid: 'V-223354'
  tag rid: 'SV-223354r879887_rule'
  tag stig_id: 'O365-OU-000009'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-25015r442282_fix'
  tag 'documentable'
  tag legacy: ['SV-108887', 'V-99783']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
