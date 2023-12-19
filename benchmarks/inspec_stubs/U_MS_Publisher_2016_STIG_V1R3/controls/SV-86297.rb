control 'SV-86297' do
  title 'Fatally corrupt files must be blocked from opening.'
  desc 'When disabled, fatally corrupt files are prevented from opening. When enabled, the user is warned but may choose to open the file.By default, fatally corrupt files are prevented from opening.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2016 -> Security "Prompt to allow fatally corrupt files to open instead of blocking them" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 


HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\publisher

Criteria: If the value PromptForBadFiles is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2016 -> Security "Prompt to allow fatally corrupt files to open instead of blocking them" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Publisher 2016'
  tag check_id: 'C-71979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71673'
  tag rid: 'SV-86297r1_rule'
  tag stig_id: 'DTOO322'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
