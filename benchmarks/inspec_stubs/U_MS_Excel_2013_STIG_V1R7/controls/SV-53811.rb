control 'SV-53811' do
  title 'File types must be configured to provide mismatch warnings'
  desc "Excel can load files with extensions that do not match the files' type. For example, if a comma-separated values (CSV) file named example.csv is renamed example.xls, Excel can properly load it as a CSV file.
Some attacks target specific file formats. If Excel is allowed to load files with extensions that do not match their file types, a malicious individual can deceive users into loading dangerous files that have incorrect extensions.
By default, if users attempt to open files with the wrong extension, Excel opens the file and displays a warning that the file type is not what Excel expected."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security "Force file extension to match file type" is set to "Enabled (Allow different, but warn)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\security

Criteria: If the value ExtensionHardening is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security "Force file extension to match file type" to "Enabled (Allow different, but warn)".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47883r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17621'
  tag rid: 'SV-53811r1_rule'
  tag stig_id: 'DTOO143'
  tag gtitle: 'DTOO143 - Force File Extension to match type'
  tag fix_id: 'F-46720r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
