control 'SV-223382' do
  title 'File validation in PowerPoint must be enabled.'
  desc 'This policy setting allows you to turn off the file validation feature. If you enable this policy setting, file validation will be turned off. If you disable or do not configure this policy setting, file validation will be turned on. Office Binary Documents (97-2003) are checked to see if they conform against the file format schema before they are opened.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security "Turn off file validation" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\filevalidation

If the value EnableOnLoad is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security "Turn off file validation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25055r442365_chk'
  tag severity: 'medium'
  tag gid: 'V-223382'
  tag rid: 'SV-223382r879630_rule'
  tag stig_id: 'O365-PT-000006'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25043r442366_fix'
  tag 'documentable'
  tag legacy: ['SV-108939', 'V-99835']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
