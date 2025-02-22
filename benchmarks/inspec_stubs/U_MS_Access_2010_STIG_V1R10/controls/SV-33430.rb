control 'SV-33430' do
  title 'The Default file format must be set.'
  desc 'When users create new database files, Access saves them in the new Access format. Users can change this functionality by clicking the Office button, clicking Access Options, and then selecting a file format from the Default file format list.
If a new database is created in an inappropriate format, some users might be unable to open or use it.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Miscellaneous “Default File Format” must be set to “Enabled (Access 2007)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\access\\settings

Criteria: If the value Default File Format is REG_DWORD =  0x0000000c (hex) or 12 (Decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Miscellaneous “Default File Format” to “Enabled (Access 2007)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2010'
  tag check_id: 'C-33913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17584'
  tag rid: 'SV-33430r1_rule'
  tag stig_id: 'DTOO136 - Access'
  tag gtitle: 'DTOO136 - Default file format'
  tag fix_id: 'F-29602r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
