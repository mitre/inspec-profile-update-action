control 'SV-79433' do
  title 'Adobe Reader DC must disable the Adobe Repair Installation.'
  desc 'When Repair Installation is disabled the user does not have the option (Help Menu) or functional to repair an Adobe Reader DC install.'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: 

For 32 bit:
HKEY_LOCAL_MACHINE\\Software\\Adobe\\Acrobat Reader\\DC\\Installer

For 64 bit:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Adobe\\Acrobat Reader\\DC\\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1

If the value for DisableMaintenance is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', '"Configure the following registry value:

For 32 bit:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Adobe\\Acrobat Reader\\DC\\Installer 

For 64 bit:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Wow6432Node\\Adobe\\Acrobat Reader\\DC\\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65601r2_chk'
  tag severity: 'low'
  tag gid: 'V-64943'
  tag rid: 'SV-79433r1_rule'
  tag stig_id: 'ARDC-CN-000070'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-70883r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
