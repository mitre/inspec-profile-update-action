control 'SV-223330' do
  title 'AutoRepublish in Excel must be disabled.'
  desc 'This policy setting allows administrators to disable the AutoRepublish feature in Excel. If users choose to publish Excel data to a static Web page and enable the AutoRepublish feature, Excel saves a copy of the data to the Web page every time the user saves the workbook. By default, a message dialog displays every time the user saves a published workbook when AutoRepublish is enabled. From this dialog, the user can disable AutoRepublish temporarily or permanently, or select "Do not show this message again" to prevent the dialog from appearing after every save. If the user selects "Do not show this message again", Excel will continue to automatically republish the data after every save without informing the user.

If you enable this policy setting, the AutoRepublish feature is turned off and Excel users will need to publish data to the Web manually.

If you disable or do not configure this policy setting, users can enable the AutoRepublish feature to automatically republish workbooks saved as type Web Page.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Save >> Disable AutoRepublish is to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\options

If the value for disableautorepublish is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Save >> Disable AutoRepublish to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25003r442209_chk'
  tag severity: 'medium'
  tag gid: 'V-223330'
  tag rid: 'SV-223330r508019_rule'
  tag stig_id: 'O365-EX-000021'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24991r442210_fix'
  tag 'documentable'
  tag legacy: ['SV-108839', 'V-99735']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
