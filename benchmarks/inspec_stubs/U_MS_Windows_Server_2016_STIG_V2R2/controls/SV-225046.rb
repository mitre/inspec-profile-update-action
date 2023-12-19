control 'SV-225046' do
  title 'Anonymous enumeration of shares must not be allowed.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26737r466040_chk'
  tag severity: 'high'
  tag gid: 'V-225046'
  tag rid: 'SV-225046r569186_rule'
  tag stig_id: 'WN16-SO-000270'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-26725r466041_fix'
  tag 'documentable'
  tag legacy: ['SV-88333', 'V-73669']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
