control 'SV-223412' do
  title 'Open/Save of Word 95 binary documents and templates must be blocked.'
  desc 'This policy setting allows you to determine whether users can open, view, edit, or save Word files with the format specified by the title of this policy setting. If you enable this policy setting, you can specify whether users can open, view, edit, or save files. The options that can be selected are below. Note: Not all options may be available for this policy setting.

- Do not block: The file type will not be blocked.
- Save blocked: Saving of the file type will be blocked.
- Open/Save blocked, use open policy: Both opening and saving of the file type will be blocked. The file will open based on the policy setting configured in the "default file block behavior" key.
- Block: Both opening and saving of the file type will be blocked, and the file will not open.
- Open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit the file type will not be enabled.
- Allow editing and open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit will be enabled. 

If you disable or do not configure this policy setting, the file type will not be blocked.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> File Block Settings "Word 95 binary documents and templates" is set to "Enabled: Open/Save blocked, use open policy".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\word\\security\\fileblock

If the value word95files is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> File Block Settings "Word 95 binary documents and templates" to "Enabled: Open/Save blocked, use open policy".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25085r442455_chk'
  tag severity: 'medium'
  tag gid: 'V-223412'
  tag rid: 'SV-223412r879628_rule'
  tag stig_id: 'O365-WD-000013'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25073r442456_fix'
  tag 'documentable'
  tag legacy: ['SV-109005', 'V-99901']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
