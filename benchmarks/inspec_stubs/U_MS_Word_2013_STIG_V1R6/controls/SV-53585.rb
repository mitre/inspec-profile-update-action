control 'SV-53585' do
  title 'A warning before printing that the document contains tracking changes must be provided.'
  desc 'Tracked changes or comments embedded within a document may contain sensitive, insulting, or embarrassing information that the document owner forgot, or that a contributor may have inserted.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security "Warn before printing, saving or sending a file that contains tracked changes or comments" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\options

Criteria: If the value WarnRevisions is REG_DWORD = 1, this is not a finding'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security "Warn before printing, saving or sending a file that contains tracked changes or comments" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47732r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17813'
  tag rid: 'SV-53585r2_rule'
  tag stig_id: 'DTOO303'
  tag gtitle: 'DTOO303 - Warn before printing'
  tag fix_id: 'F-46509r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
