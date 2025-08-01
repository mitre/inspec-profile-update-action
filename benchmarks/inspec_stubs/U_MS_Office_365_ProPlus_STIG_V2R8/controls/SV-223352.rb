control 'SV-223352' do
  title 'Active X One-Off forms must only be enabled to load with Outlook Controls.'
  desc 'By default, third-party ActiveX controls are not allowed to run in one-off forms in Outlook. You can change this behavior so that Safe Controls (Microsoft Forms 2.0 controls and the Outlook Recipient and Body controls) are allowed in one-off forms, or so that all ActiveX controls are allowed to run.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Allow Active X One Off Forms is set to "Enabled" "Load only Outlook Controls".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for allowactivexoneoffforms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Allow Active X One Off Forms to "Enabled" "Load only Outlook Controls".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25025r442275_chk'
  tag severity: 'medium'
  tag gid: 'V-223352'
  tag rid: 'SV-223352r879630_rule'
  tag stig_id: 'O365-OU-000007'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25013r442276_fix'
  tag 'documentable'
  tag legacy: ['SV-108883', 'V-99779']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
