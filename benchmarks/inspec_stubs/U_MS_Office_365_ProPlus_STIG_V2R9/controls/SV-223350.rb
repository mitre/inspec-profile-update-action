control 'SV-223350' do
  title 'Files dragged from an Outlook e-mail to the file system must be created in ANSI format.'
  desc 'This policy setting controls whether e-mail messages dragged from Outlook to the file system are saved in Unicode or ANSI format.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Other >> Advanced >> Use Unicode format when dragging e-mail message to file system is set to "Disabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\options\\general

If the value for msgformat is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Other >> Advanced >> Use Unicode format when dragging e-mail message to file system to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25023r442269_chk'
  tag severity: 'medium'
  tag gid: 'V-223350'
  tag rid: 'SV-223350r879887_rule'
  tag stig_id: 'O365-OU-000005'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-25011r442270_fix'
  tag 'documentable'
  tag legacy: ['SV-108879', 'V-99775']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
