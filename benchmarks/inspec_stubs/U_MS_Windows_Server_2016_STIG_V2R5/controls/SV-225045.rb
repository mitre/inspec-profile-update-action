control 'SV-225045' do
  title 'Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous logon users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26736r466037_chk'
  tag severity: 'high'
  tag gid: 'V-225045'
  tag rid: 'SV-225045r569186_rule'
  tag stig_id: 'WN16-SO-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26724r466038_fix'
  tag 'documentable'
  tag legacy: ['SV-88331', 'V-73667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
