control 'SV-228461' do
  title 'IE Trusted Zones assumed trusted must be blocked.'
  desc 'This policy setting controls whether pictures from sites in the Trusted Sites security zone are automatically downloaded in Outlook e-mail messages and other items. If you enable this policy setting, Outlook does not automatically download content from Web sites in the Trusted sites zone in Internet Explorer. Recipients can choose to download external content on a message-by-message basis. If you disable or do not configure this policy setting, Outlook automatically downloads content from Web sites in the Trusted sites zone in Internet Explorer.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Block Trusted Zones" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value TrustedZone is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Block Trusted Zones" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30694r497705_chk'
  tag severity: 'medium'
  tag gid: 'V-228461'
  tag rid: 'SV-228461r508021_rule'
  tag stig_id: 'DTOO273'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30679r497706_fix'
  tag 'documentable'
  tag legacy: ['SV-85867', 'V-71243']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
