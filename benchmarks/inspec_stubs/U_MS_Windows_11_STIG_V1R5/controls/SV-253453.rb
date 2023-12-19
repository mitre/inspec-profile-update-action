control 'SV-253453' do
  title 'Anonymous enumeration of SAM accounts must not be allowed.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56906r829441_chk'
  tag severity: 'high'
  tag gid: 'V-253453'
  tag rid: 'SV-253453r829443_rule'
  tag stig_id: 'WN11-SO-000145'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56856r829442_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
