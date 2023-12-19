control 'SV-33875' do
  title 'Configuration for file validation must be enforced.'
  desc 'Office Binary Documents (97-2003) are checked to see if they conform against the file format schema before they are opened.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security “Turn off file validation” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\filevalidation

Criteria: If the value EnableOnLoad is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security “Turn off file validation” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34249r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26592'
  tag rid: 'SV-33875r1_rule'
  tag stig_id: 'DTOO119 - Word'
  tag gtitle: 'DTOO119 - Turn off file validation'
  tag fix_id: 'F-29943r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
