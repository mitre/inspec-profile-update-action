control 'SV-88195' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only support SMBv1.'
  desc 'check', 'If the following registry value is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\

Value Name: Start

Type: REG_DWORD
Value: 0x00000004 (4)

If the following registry value includes MRxSmb10, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\

Value Name: DependOnService

Type: REG_MULTI_SZ
Value: Default values after removing MRxSmb10 include the following, which are not a finding:
Bowser
MRxSmb20
NSI'
  desc 'fix', 'Configure the following registry values to disable the SMBv1 protocol on the SMB client.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\

Value Name: Start

Type: REG_DWORD
Value: 0x00000004 (4)

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\

Value Name: DependOnService

Type: REG_MULTI_SZ
Value: Default values after removing MRxSmb10 include the following:
Bowser
MRxSmb20
NSI

The system must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-75975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73523'
  tag rid: 'SV-88195r2_rule'
  tag stig_id: 'WIN00-000180'
  tag gtitle: 'WIN00-000180'
  tag fix_id: 'F-82929r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
