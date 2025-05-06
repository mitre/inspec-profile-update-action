control 'SV-254462' do
  title 'Windows Server 2022 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.'
  desc 'Some non-Microsoft SMB servers only support unencrypted (plain-text) password authentication. Sending plain-text passwords across the network when authenticating to an SMB server reduces the overall security of the environment. Check with the vendor of the SMB server to determine if there is a way to support encrypted password authentication.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name:  EnablePlainTextPassword

Value Type:  REG_DWORD
Value:  0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Microsoft Network Client: Send unencrypted password to third-party SMB servers to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57947r849200_chk'
  tag severity: 'medium'
  tag gid: 'V-254462'
  tag rid: 'SV-254462r849202_rule'
  tag stig_id: 'WN22-SO-000180'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-57898r849201_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
