control 'SV-223390' do
  title 'Publisher must be configured to prompt the user when another application programmatically opens a macro.'
  desc 'This policy setting controls whether the specified Office application notifies users when unsigned application add-ins are loaded or silently disable such add-ins without notification. This policy setting only applies if you enable the "Require that application add-ins are signed by Trusted Publisher" policy setting, which prevents users from changing this policy setting.

If you enable this policy setting, applications automatically disable unsigned add-ins without informing users.
 
If you disable this policy setting, if this application is configured to require that all add-ins be signed by a trusted publisher, any unsigned add-ins the application loads will be disabled and the application will display the Trust Bar at the top of the active window. The Trust Bar contains a message that informs users about the unsigned add-in.

If you do not configure this policy setting, the disable behavior applies, and in addition, users can configure this requirement themselves in the "Add-ins" category of the Trust Center for the application.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Publisher 2016 >> Security >> Publisher Automation Security Level is set to "Enabled" "By UI (prompted)".
 
Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\common\\security

If the value automationsecuritypublisher is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Publisher 2016 >> Security >> Publisher Automation Security Level to "Enabled" "By UI (prompted)"'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25063r442389_chk'
  tag severity: 'medium'
  tag gid: 'V-223390'
  tag rid: 'SV-223390r508019_rule'
  tag stig_id: 'O365-PU-000001'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25051r442390_fix'
  tag 'documentable'
  tag legacy: ['SV-108961', 'V-99857']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
