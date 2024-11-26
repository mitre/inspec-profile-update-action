control 'SV-223393' do
  title 'VBA Macros not digitally signed must be blocked in Visio.'
  desc 'This policy setting controls how the specified applications warn users when Visual Basic for Applications (VBA) macros are present.

If you enable this policy setting, you can choose from four options for determining how the specified applications will warn the user about macros:

- Disable all with notification: The application displays the Trust Bar for all macros, whether signed or unsigned. This option enforces the default configuration in Office. This option also allows users to potentially enable unsigned/untrusted macros.  If a site requires the use of macros, they must be signed /approved and added to appropriate locations listed in the Trust Center Settings. 
- Disable all except digitally signed macros: The application displays the Trust Bar for digitally signed macros, allowing users to enable them or leave them disabled. Any unsigned macros are disabled, and users are not notified.
- Disable all without notification: The application disables all macros, whether signed or unsigned, and does not notify users.
- Enable all macros (not recommended): All macros are enabled, whether signed or unsigned. This option can significantly reduce security by allowing dangerous code to run undetected.

If you disable this policy setting, "Disable all with notification" will be the default setting.

If you do not configure this policy setting, when users open files in the specified applications that contain VBA macros, the applications open the files with the macros disabled and display the Trust Bar with a warning that macros are present and have been disabled. Users can inspect and edit the files if appropriate, but cannot use any disabled functionality until they enable it by clicking "Enable Content" on the Trust Bar. If the user clicks "Enable Content", then the document is added as a trusted document.

Important: If "Disable all except digitally signed macros" is selected, users will not be able to open unsigned Access databases.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates/Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> VBA Macro Notification Settings is set to "Enabled" and "Disable all except digitally signed macros".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\visio\\security

If the value for vbawarnings is REG_DWORD = 3, this is not a finding. A value of REG_DWORD =  4 is also acceptable. If the registry key does not exist or is not configured properly, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates/Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> VBA Macro Notification Settings to "Enabled" and select "Disable all except digitally signed macros".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25066r928382_chk'
  tag severity: 'medium'
  tag gid: 'V-223393'
  tag rid: 'SV-223393r928383_rule'
  tag stig_id: 'O365-VI-000001'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-25054r442399_fix'
  tag 'documentable'
  tag legacy: ['SV-108967', 'V-99863']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
