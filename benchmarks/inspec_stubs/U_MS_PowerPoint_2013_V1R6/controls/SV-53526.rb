control 'SV-53526' do
  title 'Attachments opened from Outlook must be in Protected View.'
  desc 'This policy setting allows for determining if PowerPoint files in Outlook attachments open in Protected View. If enabling this policy setting, Outlook attachments do not open in Protected View. If disabling or not configuring this policy setting, Outlook attachments open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Turn off Protected View for attachments opened from Outlook" is set to "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\security\\protectedview

Criteria: If the value DisableAttachmentsInPV  is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Turn off Protected View for attachments opened from Outlook" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-47692r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26617'
  tag rid: 'SV-53526r2_rule'
  tag stig_id: 'DTOO293'
  tag gtitle: 'DTOO293 - Turn off Protected View for attachments'
  tag fix_id: 'F-46453r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
