control 'SV-253288' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only support SMBv1.'
  desc 'check', 'Different methods are available to disable SMBv1 on Windows 11, if WN11-00-000160is configured, this is NA.

If the following registry value is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\

Value Name: Start

Type: REG_DWORD
Value: 0x00000004 (4)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure MrxSmb10 driver".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories, respectively.  

The system must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56741r828946_chk'
  tag severity: 'medium'
  tag gid: 'V-253288'
  tag rid: 'SV-253288r828948_rule'
  tag stig_id: 'WN11-00-000170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56691r828947_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
