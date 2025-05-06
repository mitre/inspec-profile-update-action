control 'SV-29584' do
  title 'Disallow AutoPlay/Autorun from Autorun.inf'
  desc 'This registry key will prevent the autorun.inf from executing commands.'
  desc 'check', 'In the Registry Editor, navigate to the following registry key:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping\\Autorun.inf
Value Name:	 (Default)
Type:  REG_Sz
Value:  @SYS:DoesNotExist

If the above listed registry value does not exist, then this is a finding.'
  desc 'fix', 'Add the registry value as specified in the manual check.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-20130r2_chk'
  tag severity: 'high'
  tag gid: 'V-17900'
  tag rid: 'SV-29584r1_rule'
  tag gtitle: 'Disallow AutoPlay/Autorun from Autorun.inf'
  tag fix_id: 'F-18240r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
