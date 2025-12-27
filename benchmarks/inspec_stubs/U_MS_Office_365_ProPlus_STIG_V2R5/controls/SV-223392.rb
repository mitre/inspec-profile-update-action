control 'SV-223392' do
  title 'Publisher must disable all unsigned VBA macros.'
  desc 'This policy setting controls how the specified applications warn users when Visual Basic for Applications (VBA) macros are present.

If you enable this policy setting, you can choose from four options for determining how the specified applications will warn the user about macros:
 
- Disable all with notification: The application displays the Trust Bar for all macros, whether signed or unsigned. This option enforces the default configuration in Office.
- Disable all except digitally signed macros: The application displays the Trust Bar for digitally signed macros, allowing users to enable them or leave them disabled. Any unsigned macros are disabled, and users are not notified.
- Disable all without notification: The application disables all macros, whether signed or unsigned, and does not notify users.
- Enable all macros (not recommended): All macros are enabled, whether signed or unsigned. This option can significantly reduce security by allowing dangerous code to run undetected.
 
If you disable this policy setting, "Disable all with notification" will be the default setting.
 
If you do not configure this policy setting, when users open files in the specified applications that contain VBA macros, the applications open the files with the macros disabled and display the Trust Bar with a warning that macros are present and have been disabled. Users can inspect and edit the files if appropriate, but cannot use any disabled functionality until they enable it by clicking "Enable Content" on the Trust Bar. If the user clicks "Enable Content", then the document is added as a trusted document.
 
Important: If "Disable all except digitally signed macros" is selected, users will not be able to open unsigned Access databases.
 
Also, note that Microsoft Office stores certificates for trusted publishers in the Internet Explorer trusted publisher store. Earlier versions of Microsoft Office stored trusted publisher certificate information (specifically, the certificate thumbprint) in a special Office trusted publisher store. Microsoft Office still reads trusted publisher certificate information from the Office trusted publisher store, but it does not write information to this store.
 
Therefore, if you created a list of trusted publishers in a previous version of Microsoft Office and you upgrade to Office, your trusted publisher list will still be recognized. However, any trusted publisher certificates that you add to the list will be stored in the Internet Explorer trusted publisher store.'
  desc 'check', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Publisher 2016 >> Security >> Trust Center >> VBA Macro Notification Settings >> VBA Macro Notification Settings to "Enabled" "Disable all except digitally signed macros"
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\publisher\\security

If the value vbawarnings is REG_DWORD = 3, this is not a finding. Values of REG_DWORD = 2 or 4 are also acceptable. If the registry key does not exist or the value is REG_DWORD =1, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Publisher 2016 >> Security >> Trust Center >> VBA Macro Notification Settings >> VBA Macro Notification Settings must be set to "Enabled" and "Disable all except digitally signed macros".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25065r811503_chk'
  tag severity: 'medium'
  tag gid: 'V-223392'
  tag rid: 'SV-223392r822348_rule'
  tag stig_id: 'O365-PU-000003'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-25053r822347_fix'
  tag 'documentable'
  tag legacy: ['SV-108965', 'V-99861']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
