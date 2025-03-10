control 'SV-223339' do
  title 'Untrusted database files must be opened in Excel in Protected View mode.'
  desc 'This policy setting controls whether database files (.dbf) opened from an untrusted location are always opened in Protected View.

If you enable this policy setting, database files opened from an untrusted location are always opened in Protected View. Users will not be able to change this setting under File >> Options >> Trust Center >> Trust Center Settings >> Protected View.

If you disable or do not configure this policy setting, database files opened from an untrusted location are not opened in Protected View, unless users have changed this setting in the Trust Center.

Note: This policy setting only applies to subscription versions of Office, such as Office 365 ProPlus.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Always open untrusted database files in Protected View is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview

If the value for enabledatabasefileprotectedview is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Always open untrusted database files in Protected View to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25012r840161_chk'
  tag severity: 'medium'
  tag gid: 'V-223339'
  tag rid: 'SV-223339r840162_rule'
  tag stig_id: 'O365-EX-000030'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25000r572105_fix'
  tag 'documentable'
  tag legacy: ['SV-108857', 'V-99753']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
