control 'SV-228463' do
  title 'Intranet with Safe Zones for automatic picture downloads must be configured.'
  desc 'This policy setting controls whether pictures and external content in HTML e-mail messages from untrusted senders on the local intranet are downloaded without Outlook users explictly choosing to do so. If you enable this policy setting, Outlook will automatically download external content in all e-mail messages sent over the local intranet and users will not be able to change the setting. If you disable or do not configure this policy setting, Outlook does not consider the local intranet a safe zone, which means that Outlook will not automatically download content from other servers in the Local Intranet zone unless the sender is included in the Safe Senders list. Recipients can choose to download external content from untrusted senders on a message-by-message basis.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Include Intranet in Safe Zones for Automatic Picture Download" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value Intranet is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Include Intranet in Safe Zones for Automatic Picture Download" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30696r497711_chk'
  tag severity: 'medium'
  tag gid: 'V-228463'
  tag rid: 'SV-228463r508021_rule'
  tag stig_id: 'DTOO275'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30681r497712_fix'
  tag 'documentable'
  tag legacy: ['V-71247', 'SV-85871']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
