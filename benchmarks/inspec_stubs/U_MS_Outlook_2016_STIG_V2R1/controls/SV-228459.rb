control 'SV-228459' do
  title 'Automatic download content for email in Safe Senders list must be disallowed.'
  desc "This policy setting controls whether Outlook automatically downloads external content in e-mail from senders in the Safe Senders List or Safe Recipients List. If you enable this policy setting, Outlook automatically downloads content for e-mail from people in Safe Senders and Safe Recipients lists. If you disable this policy setting, Outlook will not automatically download content from external servers for messages sent by people listed in users' Safe Senders Lists or Safe Recipients Lists. Recipients can choose to download external content on a message-by-message basis. If you do not configure this policy setting, downloads are permitted when users receive e-mail from people listed in the user's Safe Senders List or Safe Recipients List."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Automatically download content for e-mail from people in Safe Senders and Safe Recipients Lists" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value UnblockSpecificSenders is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Automatic Picture Download Settings "Automatically download content for e-mail from people in Safe Senders and Safe Recipients Lists" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30692r497699_chk'
  tag severity: 'medium'
  tag gid: 'V-228459'
  tag rid: 'SV-228459r508021_rule'
  tag stig_id: 'DTOO271'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30677r497842_fix'
  tag 'documentable'
  tag legacy: ['V-71239', 'SV-85863']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
