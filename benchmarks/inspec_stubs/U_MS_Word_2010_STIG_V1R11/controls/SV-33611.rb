control 'SV-33611' do
  title 'A warning before printing that the document contains tracking changes must be provided.'
  desc 'Tracked changes or comments embedded within a document may contain sensitive, insulting, or embarrassing information that the document owner forgot, or that a contributor may have placed.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security “Warn before printing, saving or sending a file that contains tracked changes or comments” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\options\\vpref

Criteria: If the value fWarnRevisions_1125_1 is REG_DWORD = 1 this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security “Warn before printing, saving or sending a file that contains tracked changes or comments” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17813'
  tag rid: 'SV-33611r1_rule'
  tag stig_id: 'DTOO303 - Word'
  tag gtitle: 'DTOO303 - Warn before printing'
  tag fix_id: 'F-29753r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
