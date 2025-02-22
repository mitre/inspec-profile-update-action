control 'SV-223364' do
  title 'Outlook must be configured to not run scripts in forms in which the script and the layout are contained within the message.'
  desc 'This policy setting controls whether scripts can run in Outlook forms in which the script and layout are contained within the message. If you enable this policy setting, scripts can run in one-off Outlook forms. If you disable or do not configure this policy setting, Outlook does not run scripts in forms in which the script and the layout are contained within the message. Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\\Security\\Security Form Settings" is configured to "Use Outlook Security Group Policy".'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Custom Form Security "Allow scripts in one-off Outlook forms" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

If the value EnableOneOffFormScripts is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Custom Form Security "Allow scripts in one-off Outlook forms" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25037r442311_chk'
  tag severity: 'medium'
  tag gid: 'V-223364'
  tag rid: 'SV-223364r879630_rule'
  tag stig_id: 'O365-OU-000019'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25025r442312_fix'
  tag 'documentable'
  tag legacy: ['SV-108907', 'V-99803']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
