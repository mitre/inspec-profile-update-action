control 'SV-85591' do
  title 'Blocking as default file block opening behavior must be enforced.'
  desc 'This policy setting allows you to determine if users can open, view, or edit Excel files. If you enable this policy setting, you can set one of these options:- Blocked files are not opened- Blocked files open in Protected View and can not be edited- Blocked files open in Protected View and can be edited.  If you disable or do not configure this policy setting, the behavior is the same as the "Blocked files are not opened" setting.  Users will not be able to open blocked files.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> File Block Settings "Set default file block behavior" is set to "Enabled: Blocked files are not opened".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\fileblock

Criteria: If the value OpenInProtectedView is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> File Block Settings "Set default file block behavior" to "Enabled: Blocked files are not opened".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71395r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70967'
  tag rid: 'SV-85591r1_rule'
  tag stig_id: 'DTOO110'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77299r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
