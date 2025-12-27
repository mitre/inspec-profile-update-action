control 'SV-253459' do
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol.  This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u\\

Value Name: AllowOnlineID

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56912r829459_chk'
  tag severity: 'medium'
  tag gid: 'V-253459'
  tag rid: 'SV-253459r829461_rule'
  tag stig_id: 'WN11-SO-000185'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56862r829460_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
