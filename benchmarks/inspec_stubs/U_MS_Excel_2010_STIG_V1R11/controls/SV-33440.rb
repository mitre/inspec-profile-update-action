control 'SV-33440' do
  title 'File types must be configured to provide mismatch warnings.'
  desc "Excel can load files with extensions that do not match the files' type. For example, if a comma-separated values (CSV) file named example.csv is renamed example.xls, Excel can properly load it as a CSV file.
Some attacks target specific file formats. If Excel is allowed to load files with extensions that do not match their file types, a malicious person can deceive users into loading dangerous files that have incorrect extensions.
By default, if users attempt to open files with the wrong extension, Excel opens the file and displays a warning that the file type is not what Excel expected."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security “Force file extension to match file type” must be set to “Enabled (Allow different, but warn)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security

Criteria: If the value ExtensionHardening is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security “Force file extension to match file type” to “Enabled (Allow different, but warn)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33923r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17621'
  tag rid: 'SV-33440r1_rule'
  tag stig_id: 'DTOO143 - Excel'
  tag gtitle: 'DTOO143 - Force File Extension to match type'
  tag fix_id: 'F-29612r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
