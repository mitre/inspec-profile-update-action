control 'SV-226050' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only support SMBv1.'
  desc 'check', 'This requirement specifically applies to Windows 2012 but can also be used for Windows 2012 R2.

Different methods are available to disable SMBv1 on Windows 2012 R2, if V-73805 is configured on Windows 2012 R2, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Configure SMBv1 Server" to "Disabled".

The system must be restarted for the change to take effect.

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27752r475473_chk'
  tag severity: 'medium'
  tag gid: 'V-226050'
  tag rid: 'SV-226050r794701_rule'
  tag stig_id: 'WN12-00-000170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27740r794700_fix'
  tag 'documentable'
  tag legacy: ['SV-88193', 'V-73519']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
