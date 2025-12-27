control 'SV-53584' do
  title 'The automatically update links feature must be disabled.'
  desc "When users open documents Word automatically updates any links to external content, such as graphics, Excel worksheets, and PowerPoint slides. To disable automatic updating, the user can click the Office Button, click Word Options, click Advanced, scroll to the General section, and then clear the Update automatic links at open check box.
If Word is configured to automatically update links when documents are open, document content can change without the user's knowledge, which could put important information at risk."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Advanced "Update automatic links at Open" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\options

Criteria: If the value DontUpdateLinks is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Advanced "Update automatic links at Open" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17811'
  tag rid: 'SV-53584r1_rule'
  tag stig_id: 'DTOO302'
  tag gtitle: "DTOO302 - Don't update Links at Open"
  tag fix_id: 'F-46508r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
