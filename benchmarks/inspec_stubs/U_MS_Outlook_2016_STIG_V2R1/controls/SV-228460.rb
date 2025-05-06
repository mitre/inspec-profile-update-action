control 'SV-228460' do
  title 'Permit download of content from safe zones must be configured.'
  desc 'This policy setting controls whether Outlook automatically downloads content from safe zones when displaying messages. If you enable this policy setting content from safe zones will be downloaded automatically. If you disable this policy Outlook will not automatically download content from safe zones. Recipients can choose to download external content from untrusted senders on a message-by-message basis. If you do not configure this policy setting, Outlook automatically downloads content from sites that are considered "safe," as defined in the Security tab of the Internet Options dialog box in Internet Explorer. Important - Note that this policy setting is "backward." Despite the name, disabling the policy setting prevents the download of content from safe zones and enabling the policy setting allows it.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Do not permit download of content from safe zones" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value UnblockSafeZone is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Do not permit download of content from safe zones" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30693r497702_chk'
  tag severity: 'medium'
  tag gid: 'V-228460'
  tag rid: 'SV-228460r508021_rule'
  tag stig_id: 'DTOO272'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30678r497703_fix'
  tag 'documentable'
  tag legacy: ['SV-85865', 'V-71241']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
