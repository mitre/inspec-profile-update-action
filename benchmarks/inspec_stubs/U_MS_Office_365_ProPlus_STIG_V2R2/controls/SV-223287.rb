control 'SV-223287' do
  title 'Custom user interface (UI) code must be blocked from loading in all Office applications.'
  desc 'This policy setting controls whether Office 365 ProPlus applications load any custom user interface (UI) code included with a document or template. Office 365 ProPlus allows developers to extend the UI with customization code that is included in a document or template. 

If this policy setting is enabled, Office 365 ProPlus applications cannot load any UI customization code included with documents and templates. 

If this policy setting is not configured or disabled, Office 365 ProPlus applications load any UI customization code included with a document or template when opening it.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Global Options >> Customize >> Disable UI extending from documents and templates is set to Enabled: Disallow in Word; Excel; PowerPoint; Access; Outlook; Publisher; Project; Visio; InfoPath

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\toolbars

If the value noextensibilitycustomizationfromdocument is REG_DWORD = 1 for all installed Office programs, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Global Options >> Customize >> Disable UI extending from documents and templates to Enabled: Disallow in Word; Excel; PowerPoint; Access; Outlook; Publisher; Project; Visio; InfoPath.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24960r442080_chk'
  tag severity: 'medium'
  tag gid: 'V-223287'
  tag rid: 'SV-223287r508019_rule'
  tag stig_id: 'O365-CO-000004'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24948r442081_fix'
  tag 'documentable'
  tag legacy: ['SV-108751', 'V-99647']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
