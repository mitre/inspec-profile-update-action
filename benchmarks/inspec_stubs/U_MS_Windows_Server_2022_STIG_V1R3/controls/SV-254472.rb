control 'SV-254472' do
  title 'Windows Server 2022 must prevent PKU2U authentication using online identities.'
  desc 'PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u\\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: Allow PKU2U authentication requests to this computer to use online identities to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57957r849230_chk'
  tag severity: 'medium'
  tag gid: 'V-254472'
  tag rid: 'SV-254472r849232_rule'
  tag stig_id: 'WN22-SO-000280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57908r849231_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
