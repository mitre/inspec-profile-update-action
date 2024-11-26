control 'SV-85289' do
  title 'The Save commands default file format must be configured.'
  desc 'This policy setting governs the default format for new presentation files that users create. If you enable this policy setting, when a user creates a new blank presentation, it is in the specified default format.  Users may still override the default and specify a specific format when they create a presentation. If you disable or do not configure this policy setting, PowerPoint Presentation is the default option.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Save "default file format" is set to "Enabled: PowerPoint Presentation (*.pptx)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\options 

Criteria: If the value DefaultFormat is REG_DWORD = 1b (hex) or 27 (decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Save "default file format" to "Enabled: PowerPoint Presentation (*.pptx)".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71067r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70667'
  tag rid: 'SV-85289r1_rule'
  tag stig_id: 'DTOO139'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-76911r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
