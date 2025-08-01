control 'SV-223342' do
  title 'Files failing file validation must be opened in Excel in Protected view mode and disallow edits.'
  desc 'This policy setting controls how Office handles documents when they fail file validation. 

If you enable this policy setting, you can configure the following options for files that fail file validation:
- Block files completely. Users cannot open the files.
- Open files in Protected View and disallow edit. Users cannot edit the files. This is also how Office handles the files if you disable this policy setting.
- Open files in Protected View and allow edit. Users can edit the files. This is also how Office handles the files if you do not configure this policy setting.

If you disable this policy setting, Office follows the "Open files in Protected View and disallow edit" behavior.

If you do not configure this policy setting, Office follows the "Open files in Protected View and allow edit" behavior.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Set document behavior if file validation fails is set to "Enabled: Open in Protected View". Verify the check box for "Allow edit" is not selected.

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Excel\\security\\filevalidation

If the value openinprotectedview does not exist, this is not a finding. 

If both the value for openinprotectedview is REG_DWORD = 1 and the value for DisableEditFromPV is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Set document behavior if file validation fails to "Enabled: Open in Protected View". 

Uncheck the "Allow edit" check box.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25015r442245_chk'
  tag severity: 'medium'
  tag gid: 'V-223342'
  tag rid: 'SV-223342r879630_rule'
  tag stig_id: 'O365-EX-000033'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25003r442246_fix'
  tag 'documentable'
  tag legacy: ['SV-108863', 'V-99759']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
