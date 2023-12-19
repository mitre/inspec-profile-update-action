control 'SV-225493' do
  title 'Anonymous enumeration of shares must be restricted.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27192r471821_chk'
  tag severity: 'high'
  tag gid: 'V-225493'
  tag rid: 'SV-225493r569185_rule'
  tag stig_id: 'WN12-SO-000052'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27180r471822_fix'
  tag 'documentable'
  tag legacy: ['SV-52847', 'V-1093']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
