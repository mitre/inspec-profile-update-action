control 'SV-226323' do
  title 'The system must be configured to use the Classic security model.'
  desc 'Windows includes two network-sharing security models - Classic and Guest only.  With the Classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: ForceGuest

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28025r476813_chk'
  tag severity: 'medium'
  tag gid: 'V-226323'
  tag rid: 'SV-226323r794550_rule'
  tag stig_id: 'WN12-SO-000060'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-28013r476814_fix'
  tag 'documentable'
  tag legacy: ['SV-52891', 'V-3378']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
