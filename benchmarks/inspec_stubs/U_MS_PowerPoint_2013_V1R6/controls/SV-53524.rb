control 'SV-53524' do
  title 'Document behavior if file validation fails must be set.'
  desc 'This policy key controls the behavior of how Office documents should be handled when failing file validation. By requiring such documents to be opened in Protected View, any potentially malicious code would be disabled, allowing the user to edit the document and resave correctly.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Set document behavior if file validation fails" must be "Enabled: Open in Protected View" and Unchecked for "Do not allow edit".

Procedure: Use the Windows Registry Editor to navigate to the following keys: 


If both
HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\security\\filevalidation\\OpenInProtectedView is set to REG_DWORD = 1 and HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\security\\filevalidation\\DisableEditFromPV is set to REG_DWORD = 1, this is not a finding.

If either, or both keys are not set to REG_DWORD = 1, this is an open finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Set document behavior if file validation fails" to "Enabled: Open in Protected View" and Unchecked for "Do not allow edit".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-47691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26616'
  tag rid: 'SV-53524r1_rule'
  tag stig_id: 'DTOO292'
  tag gtitle: 'DTOO292 - Set document behavior'
  tag fix_id: 'F-46451r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
