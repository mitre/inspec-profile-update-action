control 'SV-238032' do
  title 'Automation Security to enforce macro level security in Office documents must be configured.'
  desc 'This policy setting controls whether macros can run in an Office 2016 application that is opened programmatically by another application. If you enable this policy setting, you can choose from three options for controlling macro behavior in Excel, PowerPoint, and Word when the application is opened programmatically: - Disable macros by default - All macros are disabled in the programmatically opened application. - Macros enabled (default) - Macros can run in the programmatically opened application. This option enforces the default configuration in Excel, PowerPoint, and Word. - User application macro security level - Macro functionality is determined by the setting in the "Macro Settings" section of the Trust Center. If you disable or do not configure this policy setting, when a separate program is used to launch Microsoft Excel, PowerPoint, or Word programmatically, any macros can run in the programmatically opened application without being blocked.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Automation Security" is set to "Enabled (Use application macro security level)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security

Criteria: If the value AutomationSecurity is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Automation Security" to "Enabled (Use application macro security level)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41242r650661_chk'
  tag severity: 'medium'
  tag gid: 'V-238032'
  tag rid: 'SV-238032r650663_rule'
  tag stig_id: 'DTOO193'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-41201r650662_fix'
  tag 'documentable'
  tag legacy: ['SV-85497', 'V-70873']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
