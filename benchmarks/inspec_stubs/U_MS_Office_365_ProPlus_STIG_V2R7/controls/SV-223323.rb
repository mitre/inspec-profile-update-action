control 'SV-223323' do
  title 'Open/save of Excel 95 workbooks must be blocked.'
  desc 'This policy setting allows you to determine whether users can open, view, edit, or save Excel files with the format specified by the title of this policy setting. If you enable this policy setting, you can specify whether users can open, view, edit, or save files. The options that can be selected are below. Note: Not all options may be available for this policy setting.

- Do not block: The file type will not be blocked.
- Save blocked: Saving of the file type will be blocked.
- Open/Save blocked, use open policy: Both opening and saving of the file type will be blocked. The file will open based on the policy setting configured in the "default file block behavior" key.
- Block: Both opening and saving of the file type will be blocked, and the file will not open.
- Open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit the file type will not be enabled.
- Allow editing and open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit will be enabled. 

If you disable or do not configure this policy setting, the file type will not be blocked.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> File Block Settings >> Excel 95 workbooks is set to "Open/Save blocked, use open policy".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\fileblock

If the value for xl9597workbooksandtemplates is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> File Block Settings >> Excel 95 workbooks to "Open/Save blocked, use open policy".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24996r442188_chk'
  tag severity: 'medium'
  tag gid: 'V-223323'
  tag rid: 'SV-223323r508019_rule'
  tag stig_id: 'O365-EX-000014'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24984r442189_fix'
  tag 'documentable'
  tag legacy: ['SV-108825', 'V-99721']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
