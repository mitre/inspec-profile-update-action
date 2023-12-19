control 'SV-223359' do
  title 'The Outlook Security Mode must be enabled to always use the Outlook Security Group Policy.'
  desc %q(This policy setting controls which set of security settings are enforced in Outlook. If you enable this policy setting, you can choose from four options for enforcing Outlook security settings: 
 
- Outlook Default Security - This option is the default configuration in Outlook. Users can configure security themselves, and Outlook ignores any security-related settings configured in Group Policy. 
- Use Security Form from "Outlook Security Settings" Public Folder - Outlook uses the settings from the security form published in the designated public folder. 
- Use Security Form from "Outlook 10 Security Settings" Public Folder - Outlook uses the settings from the security form published in the designated public folder. 
- Use Outlook Security Group Policy - Outlook uses security settings from Group Policy. Important: You must enable this policy setting if you want to apply the other Outlook security policy settings mentioned in this guide. If you disable or do not configure this policy setting, Outlook users can configure security for themselves, and Outlook ignores any security-related settings that are configured in Group Policy. 

Note: In previous versions of Outlook, when security settings were published in a form in Exchange Server public folders, users who needed these settings required the HKEY_CURRENT_USER >> Software >> Policies >> Microsoft >> Security >> CheckAdminSettings registry key to be set on their computers for the settings to apply. In Outlook, the CheckAdminSettings registry key is no longer used to determine users' security settings. Instead, the Outlook Security Mode setting can be used to determine whether Outlook security should be controlled directly by Group Policy, by the security form from the Outlook Security Settings Public Folder, or by the settings on users' own computers.)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Outlook Security Mode is set to "Enabled (Use Outlook Security Group Policy)".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for adminsecuritymode is set to REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Outlook Security Mode to "Enabled (Use Outlook Security Group Policy)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25032r811492_chk'
  tag severity: 'medium'
  tag gid: 'V-223359'
  tag rid: 'SV-223359r811493_rule'
  tag stig_id: 'O365-OU-000014'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-25020r442297_fix'
  tag 'documentable'
  tag legacy: ['SV-108897', 'V-99793']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
