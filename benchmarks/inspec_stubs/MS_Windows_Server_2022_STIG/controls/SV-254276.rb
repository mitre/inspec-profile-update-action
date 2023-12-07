control 'SV-254276' do
  title 'Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.'
  desc 'check', 'Different methods are available to disable SMBv1 on Windows Server 2022, if WN22-00-000380 is configured, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> Configure SMBv1 Server to "Disabled".

The system must be restarted for the change to take effect.

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57761r848642_chk'
  tag severity: 'medium'
  tag gid: 'V-254276'
  tag rid: 'SV-254276r848644_rule'
  tag stig_id: 'WN22-00-000390'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57712r848643_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
