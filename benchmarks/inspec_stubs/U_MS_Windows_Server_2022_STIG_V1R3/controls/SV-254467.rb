control 'SV-254467' do
  title 'Windows Server 2022 must not allow anonymous enumeration of shares.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network access: Do not allow anonymous enumeration of SAM accounts and shares to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57952r849215_chk'
  tag severity: 'high'
  tag gid: 'V-254467'
  tag rid: 'SV-254467r849217_rule'
  tag stig_id: 'WN22-SO-000230'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-57903r849216_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
