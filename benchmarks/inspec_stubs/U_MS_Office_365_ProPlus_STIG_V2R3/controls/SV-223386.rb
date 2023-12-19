control 'SV-223386' do
  title 'PowerPoint attachments opened from Outlook must be in Protected View.'
  desc 'This policy setting allows for determining whether PowerPoint files in Outlook attachments open in Protected View. If enabling this policy setting, Outlook attachments do not open in Protected View. If disabling or not configuring this policy setting, Outlook attachments open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Protected View "Turn off Protected View for attachments opened from Outlook" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\protectedview

If the value DisableAttachmentsInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Protected View "Turn off Protected View for attachments opened from Outlook" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25059r442377_chk'
  tag severity: 'medium'
  tag gid: 'V-223386'
  tag rid: 'SV-223386r508019_rule'
  tag stig_id: 'O365-PT-000010'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25047r442378_fix'
  tag 'documentable'
  tag legacy: ['SV-108947', 'V-99843']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
