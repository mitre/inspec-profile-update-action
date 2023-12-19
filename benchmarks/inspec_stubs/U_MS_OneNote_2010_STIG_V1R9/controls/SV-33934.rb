control 'SV-33934' do
  title 'Data Execution Prevention must be enforced.'
  desc 'Data Execution Prevention (DEP) is a set of hardware and software technologies performing additional checks on memory to help prevent malicious code from running on a system. The primary benefit of DEP is to help prevent code execution from data pages. Enabling this setting, turns off Data Execution Prevention. As a result, malicious code takes advantage of code injection or buffer overflow vulnerabilities possibly exploiting the computer.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft OneNote 2010 -> OneNote Options -> Security -> Trust Center “Turn off Data Execution Prevention” must be set to “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\onenote\\security

Criteria: If the value EnableDEP is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft OneNote 2010 -> OneNote Options -> Security -> Trust Center “Turn off Data Execution Prevention” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft OneNote 2010'
  tag check_id: 'C-34375r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26590'
  tag rid: 'SV-33934r1_rule'
  tag stig_id: 'DTOO128 - OneNote'
  tag gtitle: 'DTOO128 - Data Execution Prevention'
  tag fix_id: 'F-30011r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
