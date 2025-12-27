control 'SV-223398' do
  title 'Visio 5.0 or earlier Binary Drawings, Templates and Stencils must be blocked.'
  desc 'This policy setting allows you to determine whether users can open or save Visio files with the format specified by the title of this policy setting.

If you enable this policy setting, you can specify whether users can open or save files.

The options that can be selected are below. Note: Not all options may be available for this policy setting.

-Do not block: The file type will not be blocked.
-Save blocked: Saving of the filet type will be blocked.
-Open/Save blocked: Both opening and saving of the file type will be blocked.

If you disable or do not configure this policy setting, the file type will be blocked.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> File Block Settings "Visio 5.0 or earlier Binary Drawings, Templates and Stencils" is set to "Enabled" and "Open/Save blocked".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\visio\\security\\fileblock

If the value "visio50andearlierfiles" is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> File Block Settings "Visio 5.0 or earlier Binary Drawings, Templates and Stencils" to "Enabled" and "Open/Save blocked".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25071r442413_chk'
  tag severity: 'medium'
  tag gid: 'V-223398'
  tag rid: 'SV-223398r879628_rule'
  tag stig_id: 'O365-VI-000006'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25059r442414_fix'
  tag 'documentable'
  tag legacy: ['SV-108977', 'V-99873']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
