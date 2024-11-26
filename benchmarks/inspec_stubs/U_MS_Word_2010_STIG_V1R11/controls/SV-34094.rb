control 'SV-34094' do
  title 'Online translation dictionaries must be in use.'
  desc 'This setting allows you to prevent online dictionaries from being used for the translation of text through the Research pane.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Miscellaneous “Use online translation dictionaries” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\research\\translation

Criteria: If the value UseOnline is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Miscellaneous “Use online translation dictionaries” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34248r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26648'
  tag rid: 'SV-34094r1_rule'
  tag stig_id: 'DTOO328 - Word'
  tag gtitle: 'DTOO328 - Use online translation dictionaries'
  tag fix_id: 'F-29942r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
