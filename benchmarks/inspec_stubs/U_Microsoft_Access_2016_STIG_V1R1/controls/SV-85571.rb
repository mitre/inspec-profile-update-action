control 'SV-85571' do
  title 'The Save commands default file format must be configured.'
  desc 'This policy setting controls whether new database files are created in the new Access format or in a format used by earlier versions of Access. If you enable this policy setting, you can specify whether new database files are created in Access 2016 format by default or in Access 2002--2003 format. Users can still override the default and select a specific format when they save the files, but cannot set the default by themselves from the Access Options dialog. If you disable or do not configure this policy setting, when users create new database files, Access saves them in the new Access 2016 format; however, users can change this functionality by selecting a file format from the Default file format drop down list under Access Options | Popular | Creating databases. Note: If you disable this policy setting, users can choose from three default file formats: Access 2000, Access 2002--2003, and Access 2016. You can use this policy setting to specify either the Access 2002--2003 or Access 2016 format as the default, but not the Access 2000 format.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Miscellaneous "Default File Format" is set to "Enabled (Access 2007)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\access\\settings

Criteria: If the value Default File Format is REG_DWORD =  0x0000000c (hex) or 12 (Decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Miscellaneous "Default File Format" to "Enabled (Access 2007)".'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2016'
  tag check_id: 'C-71375r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70947'
  tag rid: 'SV-85571r1_rule'
  tag stig_id: 'DTOO136'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-77279r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
