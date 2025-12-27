control 'SV-223406' do
  title 'The default file block behavior must be set to not open blocked files in Word.'
  desc 'This policy setting allows you to determine if users can open, view, or edit Word files.

If you enable this policy setting, you can set one of these options:
- Blocked files are not opened.
- Blocked files open in Protected View and cannot be edited.
- Blocked files open in Protected View and can be edited.

If you disable or do not configure this policy setting, the behavior is the same as the "Blocked files are not opened" setting. Users will not be able to open blocked files.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> File Block Settings "Set default file block behavior" is set to "Enabled: Blocked files are not opened".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\word\\security\\fileblock

If the value OpenInProtectedView is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> File Block Settings "Set default file block behavior" to "Enabled: Blocked files are not opened".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25079r442437_chk'
  tag severity: 'medium'
  tag gid: 'V-223406'
  tag rid: 'SV-223406r508019_rule'
  tag stig_id: 'O365-WD-000007'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25067r442438_fix'
  tag 'documentable'
  tag legacy: ['SV-108993', 'V-99889']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
