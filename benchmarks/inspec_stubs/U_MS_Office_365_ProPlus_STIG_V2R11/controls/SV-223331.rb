control 'SV-223331' do
  title 'AutoRepublish warning alert in Excel must be enabled.'
  desc 'This policy setting allows administrators to disable the AutoRepublish feature in Excel. If users choose to publish Excel data to a static Web page and enable the AutoRepublish feature, Excel saves a copy of the data to the Web page every time the user saves the workbook. By default, a message dialog displays every time the user saves a published workbook when AutoRepublish is enabled. From this dialog, the user can disable AutoRepublish temporarily or permanently, or select "Do not show this message again" to prevent the dialog from appearing after every save. If the user selects "Do not show this message again", Excel will continue to automatically republish the data after every save without informing the user.
 
If you enable this policy setting, the AutoRepublish feature is turned off and Excel users will need to publish data to the Web manually.
 
If you disable or do not configure this policy setting, users can enable the AutoRepublish feature to automatically republish workbooks saved as type Web Page.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Save >> Do not show AutoRepublish warning alert is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\options

If value for disableautorepublishwarning is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Save >> Do not show AutoRepublish warning alert to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25004r744252_chk'
  tag severity: 'medium'
  tag gid: 'V-223331'
  tag rid: 'SV-223331r879887_rule'
  tag stig_id: 'O365-EX-000022'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24992r442213_fix'
  tag 'documentable'
  tag legacy: ['SV-108841', 'V-99737']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
