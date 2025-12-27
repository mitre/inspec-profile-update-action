control 'SV-228458' do
  title 'External content and pictures in HTML email must be displayed.'
  desc %q(This policy setting setting controls whether Outlook downloads untrusted pictures and external content located in HTML e-mail messages without users explicitly choosing to download them. If you enable this policy setting, Outlook will not automatically download content from external servers unless the sender is included in the Safe Senders list. Recipients can choose to download external content from untrusted senders on a message-by-message basis. If you disable this policy setting, Outlook will display pictures and external content in HTML e-mail automatically.If you do not configure this policy setting, Outlook does not download external content in HTML e-mail and RSS items unless the content is considered safe. Content that Outlook can be configured to consider safe includes: - Content in e-mail messages from senders and to recipients defined in the Safe Senders and Safe Recipients lists. - Content from Web sites in Internet Explorer's Trusted Sites security zone. - Content in RSS items. - Content from SharePoint Discussion Boards. Users can control what content is considered safe by changing the options in the "Automatic Download" section of the Trust Center. If Outlook's default blocking configuration is overridden, in the Trust Center or by some other method, Outlook will display external content in all HTML e-mail messages, including any that include Web beacons.)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Automatic Picture Download Settings "Display pictures and external content in HTML e-mail" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value BlockExtContent is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Display pictures and external content in HTML e-mail" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30691r497696_chk'
  tag severity: 'medium'
  tag gid: 'V-228458'
  tag rid: 'SV-228458r508021_rule'
  tag stig_id: 'DTOO270'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30676r497697_fix'
  tag 'documentable'
  tag legacy: ['SV-85861', 'V-71237']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
