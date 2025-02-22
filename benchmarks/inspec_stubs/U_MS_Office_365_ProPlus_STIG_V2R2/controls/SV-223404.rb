control 'SV-223404' do
  title 'If file validation fails, files must be opened in Protected view in Word with ability to edit disabled.'
  desc 'This policy setting controls how Office handles documents when they fail file validation. 

If you enable this policy setting, you can configure the following options for files that fail file validation:
- Block files completely. Users cannot open the files.
- Open files in Protected View and disallow edit. Users cannot edit the files. This is also how Office handles the files if you disable this policy setting.
- Open files in Protected View and allow edit. Users can edit the files. This is also how Office handles the files if you do not configure this policy setting.

If you disable this policy setting, Office follows the "Open files in Protected View and disallow edit" behavior.

If you do not configure this policy setting, Office follows the "Open files in Protected View and allow edit" behavior.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Protected View >> Set document behavior if file validation fails is set to "Enabled: Open in Protected View". Verify the check box for "Allow edit" is not selected.

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\security\\filevalidation

If the value openinprotectedview does not exist, this is not a finding. 

If both the value for openinprotectedview is REG_DWORD = 1 and the value for DisableEditFromPV is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Protected View >> Set document behavior if file validation fails to "Enabled: Open in Protected View". 

Uncheck the "Allow edit" check box.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25077r442431_chk'
  tag severity: 'medium'
  tag gid: 'V-223404'
  tag rid: 'SV-223404r508019_rule'
  tag stig_id: 'O365-WD-000005'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25065r442432_fix'
  tag 'documentable'
  tag legacy: ['SV-108989', 'V-99885']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
