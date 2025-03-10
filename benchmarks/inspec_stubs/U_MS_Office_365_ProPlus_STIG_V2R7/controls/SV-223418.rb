control 'SV-223418' do
  title 'File validation in Word must be enabled.'
  desc 'This policy setting allows the file validation feature to be turned off.

If this policy setting is enabled, file validation will be turned off.

If this policy setting is disabled or not configured, file validation will be turned on. Office Binary Documents (97-2003) are checked to see if they conform to the file format schema before they are opened.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Turn off file validation is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security\\filevalidation

If the value for enableonload is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Turn off file validation to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25091r442473_chk'
  tag severity: 'medium'
  tag gid: 'V-223418'
  tag rid: 'SV-223418r508019_rule'
  tag stig_id: 'O365-WD-000019'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-25079r442474_fix'
  tag 'documentable'
  tag legacy: ['SV-109621', 'V-100517']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
