control 'SV-33434' do
  title 'Update of automatic links must be configured to prompt.'
  desc "If an Excel workbook contains links to other documents and users are not prompted to approve them, the contents of the workbook might change without the users' knowledge because the linked files have changed.
By default, users are prompted to update automatic links."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Advanced “Ask to update automatic links” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\options\\binaryoptions

Criteria: If the value fUpdateExt_78_1 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Advanced “Ask to update automatic links” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17732'
  tag rid: 'SV-33434r1_rule'
  tag stig_id: 'DTOO150 - Excel'
  tag gtitle: 'DTOO150 - Automatic Link Updates'
  tag fix_id: 'F-29606r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
