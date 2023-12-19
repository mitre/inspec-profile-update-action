control 'SV-33868' do
  title 'Document behavior if file validation fails must be set.'
  desc 'This policy key controls the behavior of how Office documents should be handled when failing File Validation. The options available are:
-Block files completely. This will prevent users from opening files.
-Open files in Protected View and disallow edit. This will prevent users from editing the files.
-Open files in Protected view and allow edit. This will allow users to edit the files.
If disabling or not configuring this policy setting, the default setting will be, "open files in protected view and allow edit".'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> Protected View “Set document behavior if file validation fails” must be "Enabled: Open in Protected View" and Unchecked for "Do not allow edit".

Procedure: Use the Windows Registry Editor to navigate to the following keys: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\filevalidation

Criteria: If the value OpenInProtectedView is REG_DWORD = 1, this is not a finding.

AND

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\filevalidation

Criteria: If the value DisableEditFromPV  is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> Protected View “Set document behavior if file validation fails” to "Enabled: Open in Protected View" and Unchecked for "Do not allow edit".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34266r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26616'
  tag rid: 'SV-33868r1_rule'
  tag stig_id: 'DTOO292 - Word'
  tag gtitle: 'DTOO292 - Set document behavior'
  tag fix_id: 'F-29955r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
