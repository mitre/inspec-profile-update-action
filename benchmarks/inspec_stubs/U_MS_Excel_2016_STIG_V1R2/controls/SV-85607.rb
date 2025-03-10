control 'SV-85607' do
  title 'Configuration for file validation must be enforced.'
  desc 'This policy setting allows you to turn off the file validation feature. If you enable this policy setting, file validation will be turned off. If you disable or do not configure this policy setting, file validation will be turned on.  Office Binary Documents (97-2003) are checked to see if they conform against the file format schema before they are opened.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security "Turn off file validation" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\filevalidation

Criteria: If the value EnableOnLoad is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security "Turn off file validation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71411r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70983'
  tag rid: 'SV-85607r2_rule'
  tag stig_id: 'DTOO119'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-77315r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
