control 'SV-223392' do
  title 'Publisher must disable all unsigned VBA macros.'
  desc 'This policy setting controls how the specified applications warn users when Visual Basic for Applications (VBA) macros are present.

If you enable this policy setting, you can choose from four options for determining how the specified applications will warn the user about macros:
 
- Disable all with notification: The application displays the Trust Bar for all macros, whether signed or unsigned. This option enforces the default configuration in Office. This option also allows users to potentially enable unsigned/untrusted macros.  If a site requires the use of macros, they must be signed /approved and added to appropriate locations listed in the Trust Center Settings. 
- Disable all except digitally signed macros: The application displays the Trust Bar for digitally signed macros, allowing users to enable them or leave them disabled. Any unsigned macros are disabled, and users are not notified.
- Disable all without notification: The application disables all macros, whether signed or unsigned, and does not notify users.
- Enable all macros (not recommended): All macros are enabled, whether signed or unsigned. This option can significantly reduce security by allowing dangerous code to run undetected.
 
If you disable this policy setting, "Disable all with notification" will be the default setting.
 
If you do not configure this policy setting, when users open files in the specified applications that contain VBA macros, the applications open the files with the macros disabled and display the Trust Bar with a warning that macros are present and have been disabled. Users can inspect and edit the files if appropriate, but cannot use any disabled functionality until they enable it by clicking "Enable Content" on the Trust Bar. If the user clicks "Enable Content", then the document is added as a trusted document.
 
Important: If "Disable all except digitally signed macros" is selected, users will not be able to open unsigned Access databases.'
  desc 'check', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Publisher 2016 >> Security >> Trust Center >> VBA Macro Notification Settings >> VBA Macro Notification Settings to "Enabled" "Disable all except digitally signed macros"
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\publisher\\security

If the value vbawarnings is REG_DWORD = 3, this is not a finding. A value of REG_DWORD =  4 is also acceptable. If the registry key does not exist or is not configured properly, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Publisher 2016 >> Security >> Trust Center >> VBA Macro Notification Settings >> VBA Macro Notification Settings must be set to "Enabled" and "Disable all except digitally signed macros".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25065r928380_chk'
  tag severity: 'medium'
  tag gid: 'V-223392'
  tag rid: 'SV-223392r928381_rule'
  tag stig_id: 'O365-PU-000003'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-25053r863219_fix'
  tag 'documentable'
  tag legacy: ['SV-108965', 'V-99861']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
