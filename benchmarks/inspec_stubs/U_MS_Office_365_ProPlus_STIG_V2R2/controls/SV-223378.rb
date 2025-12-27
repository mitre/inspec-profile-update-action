control 'SV-223378' do
  title 'The ability to run programs from PowerPoint must be disabled.'
  desc 'This policy setting controls the prompting and activation behavior for the "Run Programs" option for action buttons in PowerPoint.

If you enable this policy setting, you can choose from three options to control how the "Run Programs" option functions:
- Disable (do not run any programs). If users click an action button with the "Run Programs" action assigned to it, nothing will happen. This option enforces the default configuration in PowerPoint.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Run Programs is set to "Enabled" "Disable (do not run any programs)".
 
Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\powerpoint\\security

If the value runprograms does not exist, this is not a finding. If the value is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Run Programs to "Enabled" "Disable (do not run any programs)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25051r442353_chk'
  tag severity: 'medium'
  tag gid: 'V-223378'
  tag rid: 'SV-223378r508019_rule'
  tag stig_id: 'O365-PT-000002'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25039r442354_fix'
  tag 'documentable'
  tag legacy: ['SV-108931', 'V-99827']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
