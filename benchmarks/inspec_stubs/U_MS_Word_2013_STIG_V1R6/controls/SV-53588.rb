control 'SV-53588' do
  title 'Online translation dictionaries must not be used.'
  desc 'This setting allows you to prevent online dictionaries from being used for the translation of text through the Research pane.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Miscellaneous -> "Use online translation dictionaries" is set to Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

 HKCU\\software\\policies\\Microsoft\\office\\15.0\\common\\research\\translation

Criteria: If the value useonline is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Miscellaneous -> "Use online translation dictionaries" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47735r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26648'
  tag rid: 'SV-53588r2_rule'
  tag stig_id: 'DTOO328'
  tag gtitle: 'DTOO328 - Use online translation dictionaries'
  tag fix_id: 'F-46513r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
