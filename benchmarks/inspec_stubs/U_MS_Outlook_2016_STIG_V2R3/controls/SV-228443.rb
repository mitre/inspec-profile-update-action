control 'SV-228443' do
  title 'Scripts in One-Off Outlook forms must be disallowed.'
  desc 'This policy setting controls whether scripts can run in Outlook forms in which the script and layout are contained within the message. If you enable this policy setting, scripts can run in one-off Outlook forms. If you disable or do not configure this policy setting, Outlook does not run scripts in forms in which the script and the layout are contained within the message. Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\\Security\\Security Form Settings" is configured to "Use Outlook Security Group Policy."'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Custom Form Security "Allow scripts in one-off Outlook forms" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value EnableOneOffFormScripts is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Custom Form Security "Allow scripts in one-off Outlook forms" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30676r497651_chk'
  tag severity: 'medium'
  tag gid: 'V-228443'
  tag rid: 'SV-228443r508021_rule'
  tag stig_id: 'DTOO246'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30661r497652_fix'
  tag 'documentable'
  tag legacy: ['SV-85789', 'V-71165']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
