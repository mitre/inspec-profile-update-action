control 'SV-53632' do
  title 'Configuration for file validation must be enforced.'
  desc "Office File Validation helps detect and prevent a kind of exploit known as a file format attack or file fuzzing attack. File format attacks exploit the integrity of a file. They occur when someone modifies the structure of a file with the intent of adding malicious code. Usually the malicious code is run remotely and is used to elevate the privilege of restricted accounts on the computer. As a result, an attacker could gain access to a computer that they did not previously have access to. This could enable an attacker to read sensitive information from the computer's hard disk drive or install malware, such as a worm or a key logging program. The Office File Validation feature helps prevent file format attacks by scanning and validating files before they are opened. To validate files, Office File Validation compares a file's structure to a predefined file schema, which is a set of rules that determine what a readable file looks like. If Office File Validation detects that a file's structure does not follow all rules that are described in the schema, the file does not pass validation."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security "Turn off file validation" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\security\\filevalidation

Criteria: If the value EnableOnLoad is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security "Turn off file validation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47758r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26592'
  tag rid: 'SV-53632r1_rule'
  tag stig_id: 'DTOO119'
  tag gtitle: 'DTOO119 - Turn off file validation'
  tag fix_id: 'F-46557r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
