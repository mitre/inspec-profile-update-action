control 'SV-52773' do
  title 'Prompts to convert older databases must be enforced.'
  desc 'When users open databases that were created in the Access 97 file format, Access 2013 prompts them to convert the database to a newer file format.  Users can choose to convert the database or leave it in the older format.  Disabling this setting ensures Access 2013 prompts the user, and is therefore unlikely to cause usability issues. Otherwise, if Access 2013 was allowed to automatically convert the database, it may be converting outdated code which is not compatible or tested with the newer version. In addition, if the database is used by multiple users, there is the potential of making the database inaccessible to other users who may not be using Access 2013.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2013 -> Miscellaneous "Do not prompt to convert older databases" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\access\\settings

Criteria: If the value NoConvertDialog is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2013 -> Miscellaneous "Do not prompt to convert older databases" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Access 2013'
  tag check_id: 'C-47102r1_chk'
  tag severity: 'low'
  tag gid: 'V-17603'
  tag rid: 'SV-52773r1_rule'
  tag stig_id: 'DTOO137'
  tag gtitle: 'DTOO137 - Prompt / Convert Older Databases'
  tag fix_id: 'F-45699r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
