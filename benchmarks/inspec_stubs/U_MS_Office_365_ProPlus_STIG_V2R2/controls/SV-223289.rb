control 'SV-223289' do
  title 'Macros in all Office applications that are opened programmatically by another application must be opened based upon macro security level.'
  desc 'This policy setting controls whether macros can run in an Office 365 ProPlus application that is opened programmatically by another application. If this policy setting is enabled, the user can choose from three options for controlling macro behavior in Excel, PowerPoint, and Word when the application is opened programmatically:

- Disable macros by default ¬- all macros are disabled in the programmatically opened application. 
- Macros enabled (default) - macros can run in the programmatically opened application. This option enforces the default configuration in Excel, PowerPoint, and Word. 
- User application macro security level - macro functionality is determined by the setting in the "Macro Settings" section of the Trust Center. 

If this policy setting is disabled or not configured, when a separate program is used to launch Microsoft Excel, PowerPoint, or Word programmatically, any macros can run in the programmatically opened application without being blocked.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Automation Security" is set to "Enabled (Use application macro security level)".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security

If the value AutomationSecurity is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Automation Security" to "Enabled (Use application macro security level)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24962r442086_chk'
  tag severity: 'medium'
  tag gid: 'V-223289'
  tag rid: 'SV-223289r508019_rule'
  tag stig_id: 'O365-CO-000006'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24950r442087_fix'
  tag 'documentable'
  tag legacy: ['SV-108755', 'V-99651']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
