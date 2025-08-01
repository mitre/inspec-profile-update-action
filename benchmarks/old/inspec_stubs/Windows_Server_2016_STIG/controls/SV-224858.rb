control 'SV-224858' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.'
  desc 'check', 'Different methods are available to disable SMBv1 on Windows 2016, if V-73299 is configured, this is NA.

If the following registry value is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\

Value Name: Start

Type: REG_DWORD
Value: 0x00000004 (4)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure MrxSmb10 driver".

The system must be restarted for the changes to take effect.

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26549r465476_chk'
  tag severity: 'medium'
  tag gid: 'V-224858'
  tag rid: 'SV-224858r569186_rule'
  tag stig_id: 'WN16-00-000412'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26537r465477_fix'
  tag 'documentable'
  tag legacy: ['V-78125', 'SV-92831']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
