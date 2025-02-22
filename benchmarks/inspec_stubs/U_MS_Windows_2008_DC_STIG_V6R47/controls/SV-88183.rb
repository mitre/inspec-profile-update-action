control 'SV-88183' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only support SMBv1.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the following registry value to disable the SMBv1 protocol on the SMB server.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)

The system must be restarted for the change to take effect.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-73619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73519'
  tag rid: 'SV-88183r1_rule'
  tag stig_id: 'WIN00-000170'
  tag gtitle: 'WIN00-000170'
  tag fix_id: 'F-79987r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
