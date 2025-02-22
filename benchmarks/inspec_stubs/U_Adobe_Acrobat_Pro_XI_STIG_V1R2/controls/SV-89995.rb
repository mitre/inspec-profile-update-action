control 'SV-89995' do
  title 'Adobe Acrobat Pro XI Adobe Repair Installation must be disabled.'
  desc 'When Repair Installation is disabled the user does not have the option (Help Menu) or ability to repair an Adobe Acrobat Pro XI install. Ability to repair includes the risk that established security settings could be overwritten.'
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: 

For 32 bit:
HKEY_LOCAL_MACHINE\\Software\\Adobe\\Adobe Acrobat\\11.0\\Installer

For 64 bit:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Adobe\\Adobe Acrobat\\11.0\\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1

If the value for DisableMaintenance is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

For 32 bit:
Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Adobe\\Adobe Acrobat\\11.0\\Installer

For 64 bit:
Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\SOFTWARE\\Wow6432Node\\Adobe\\Adobe Acrobat\\11.0\\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75099r1_chk'
  tag severity: 'low'
  tag gid: 'V-75315'
  tag rid: 'SV-89995r1_rule'
  tag stig_id: 'ADBP-XI-001295'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81931r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
