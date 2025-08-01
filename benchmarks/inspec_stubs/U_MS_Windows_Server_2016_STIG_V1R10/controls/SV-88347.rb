control 'SV-88347' do
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u\\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73683'
  tag rid: 'SV-88347r1_rule'
  tag stig_id: 'WN16-SO-000340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-80133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
