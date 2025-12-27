control 'SV-33673' do
  title 'Prompts to convert older databases must be enforced.'
  desc 'When users open databases that were created in the Access 97 file format, Access 2010 prompts them to convert the database to a newer file format.  Users can choose to convert the database or leave it in the older format.  Disabling this setting enforces Access 2010 to prompt the users, and is therefore unlikely to cause usability issues.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Miscellaneous “Do not prompt to convert older databases” must be “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\access\\settings

Criteria: If the value NoConvertDialog is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Miscellaneous “Do not prompt to convert older databases” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2010'
  tag check_id: 'C-34130r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17603'
  tag rid: 'SV-33673r1_rule'
  tag stig_id: 'DTOO137 - Access'
  tag gtitle: 'DTOO137 - Prompt / Convert Older Databases'
  tag fix_id: 'F-29815r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
