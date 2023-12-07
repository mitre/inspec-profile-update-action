control 'SV-225053' do
  title 'Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. This setting controls whether a LAN Manager hash of the password is stored in the SAM the next time the password is changed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26744r466061_chk'
  tag severity: 'high'
  tag gid: 'V-225053'
  tag rid: 'SV-225053r877397_rule'
  tag stig_id: 'WN16-SO-000360'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-26732r466062_fix'
  tag 'documentable'
  tag legacy: ['V-73687', 'SV-88351']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
