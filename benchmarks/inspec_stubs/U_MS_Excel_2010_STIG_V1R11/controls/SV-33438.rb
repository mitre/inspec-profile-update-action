control 'SV-33438' do
  title 'Automatic republish to web pages must be disallowed.'
  desc 'If users choose to publish Excel data to a static Web page and enable the AutoRepublish feature, Excel saves a copy of the data to the Web page every time the user saves the workbook. If the page is on a Web server, anyone who has access to the page will be able to see the updated data after every save, which can lead to the undesired disclosure of sensitive or incorrect information.
By default, a message dialog box displays every time the user saves a published workbook when AutoRepublish is enabled. From this dialog box, the user can disable AutoRepublish temporarily or permanently, or select "Do not show this message again" to prevent the dialog box from appearing after every save. If the user selects “Do not show this message again”, Excel will continue to automatically republish the data after every save without informing the user.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Save “Disable AutoRepublish” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\options

Criteria: If the value DisableAutoRepublish is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Save “Disable AutoRepublish” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17652'
  tag rid: 'SV-33438r1_rule'
  tag stig_id: 'DTOO140 - Excel'
  tag gtitle: 'DTOO140 - Disable AutoRepublish'
  tag fix_id: 'F-29610r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
