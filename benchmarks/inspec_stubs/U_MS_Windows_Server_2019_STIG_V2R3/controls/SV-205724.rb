control 'SV-205724' do
  title 'Windows Server 2019 must not allow anonymous enumeration of shares.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5989r355090_chk'
  tag severity: 'high'
  tag gid: 'V-205724'
  tag rid: 'SV-205724r569188_rule'
  tag stig_id: 'WN19-SO-000230'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-5989r355091_fix'
  tag 'documentable'
  tag legacy: ['V-93537', 'SV-103623']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
