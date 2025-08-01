control 'SV-53255' do
  title 'Fatally corrupt files must be blocked from opening.'
  desc "Enabling this setting allows a user to open fatally corrupt Publisher 2013 files.  As a result, malicious code or users could become active on the user's computer or the network.  For example, a malicious user may purposely corrupt a Publisher file.  The corrupted file could force the application to fail or execute malicious code, giving the malicious user control of Publisher 2013."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2013 -> Security "Prompt to allow fatally corrupt files to open instead of blocking them" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 


HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\publisher

Criteria: If the value PromptForBadFiles is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2013 -> Security "Prompt to allow fatally corrupt files to open instead of blocking them" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Publisher 2013'
  tag check_id: 'C-47557r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26707'
  tag rid: 'SV-53255r1_rule'
  tag stig_id: 'DTOO322'
  tag gtitle: 'DTOO322 - Prompt files to open instead of blocking'
  tag fix_id: 'F-46184r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
