control 'SV-223338' do
  title 'Untrusted Microsoft Query files must be blocked from opening in Excel.'
  desc 'This policy setting controls whether Microsoft Query files (.iqy, oqy, .dqy, and .rqy) in an untrusted location are prevented from opening.

If you enable this policy setting, Microsoft Query files in an untrusted location are prevented from opening. Users will not be able to change this setting under File >> Options >> Trust Center >> Trust Center Settings >> External Content.

If you disable or do not configure this policy setting, Microsoft Query files in an untrusted location are not prevented from opening, unless users have changed this setting in the Trust Center.

Note: This policy setting only applies to subscription versions of Office, such as Office 365 ProPlus.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Always prevent untrusted Microsoft Query files from opening is set to "Enabled".
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\external content.
Value for enableblockunsecurequeryfiles should be REG_DWORD = 1

If the value for enableblockunsecurequeryfiles is Reg_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Always prevent untrusted Microsoft Query files from opening to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25011r684248_chk'
  tag severity: 'medium'
  tag gid: 'V-223338'
  tag rid: 'SV-223338r879628_rule'
  tag stig_id: 'O365-EX-000029'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24999r442234_fix'
  tag 'documentable'
  tag legacy: ['SV-108855', 'V-99751']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
