control 'SV-254466' do
  title 'Windows Server 2022 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous logon users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network access: Do not allow anonymous enumeration of SAM accounts to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57951r849212_chk'
  tag severity: 'high'
  tag gid: 'V-254466'
  tag rid: 'SV-254466r849214_rule'
  tag stig_id: 'WN22-SO-000220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57902r849213_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
