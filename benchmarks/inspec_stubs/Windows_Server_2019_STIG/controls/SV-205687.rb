control 'SV-205687' do
  title 'Windows Server 2019 must have WDigest Authentication disabled.'
  desc 'When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled by default in Windows Server 2019. This setting ensures this is enforced.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest\\

Value Name:  UseLogonCredential

Type:  REG_DWORD
Value:  0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "WDigest Authentication (disabling may require KB2871997)" to "Disabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and " SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5952r354979_chk'
  tag severity: 'medium'
  tag gid: 'V-205687'
  tag rid: 'SV-205687r569188_rule'
  tag stig_id: 'WN19-CC-000020'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-5952r354980_fix'
  tag 'documentable'
  tag legacy: ['SV-103487', 'V-93401']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
