control 'SV-85715' do
  title 'Online translation dictionaries must not be used.'
  desc 'This policy setting allows you to prevent online dictionaries from being used for the translation of text through the Research pane. If you enable or do not configure this policy setting, the online dictionaries can be used to translate text through the Research pane. If you disable this policy setting, the online dictionaries cannot be used to translate text through the Research pane.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Miscellaneous -> "Use online translation dictionaries" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

 HKCU\\software\\policies\\Microsoft\\office\\16.0\\common\\research\\translation

Criteria: If the value useonline is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Miscellaneous -> "Use online translation dictionaries" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2016'
  tag check_id: 'C-71519r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71091'
  tag rid: 'SV-85715r1_rule'
  tag stig_id: 'DTOO328'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77423r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
