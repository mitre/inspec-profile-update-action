control 'SV-223311' do
  title 'VBA Macros not digitally signed must be blocked in Excel.'
  desc 'This policy setting controls how the specified applications warn users when Visual Basic for Applications (VBA) macros are present.

If you enable this policy setting, you can choose from four options for determining how the specified applications will warn the user about macros:

- Disable all with notification: The application displays the Trust Bar for all macros, whether signed or unsigned. This option enforces the default configuration in Office.
- Disable all except digitally signed macros: The application displays the Trust Bar for digitally signed macros, allowing users to enable them or leave them disabled. Any unsigned macros are disabled, and users are not notified.
- Disable all without notification: The application disables all macros, whether signed or unsigned, and does not notify users.
- Enable all macros (not recommended): All macros are enabled, whether signed or unsigned. This option can significantly reduce security by allowing dangerous code to run undetected.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> "Macro Notification Settings" is set to "Enabled" and "Disable VBA macros except digitally signed macros" from the Options is selected.

Use the Windows Registry Editor to navigate to the following key:
HKCU\\software\\policies\\Microsoft\\office\\16.0\\excel\\security

If the value vbawarnings is REG_DWORD = 3, this is not a finding. A value of REG_DWORD =  4 are also acceptable. If the registry key does not exist or is not configured properly, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> "Macro Notification Settings" is set to "Enabled" and select "Disable VBA macros except digitally signed macros" from the Options.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24984r865859_chk'
  tag severity: 'medium'
  tag gid: 'V-223311'
  tag rid: 'SV-223311r865861_rule'
  tag stig_id: 'O365-EX-000002'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24972r865860_fix'
  tag 'documentable'
  tag legacy: ['SV-108801', 'V-99697']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
