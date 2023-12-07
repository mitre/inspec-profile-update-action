control 'SV-29267' do
  title 'The system is not configured to use the Classic security model.'
  desc 'Windows includes two network-sharing security models - Classic and Guest only. With the classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Sharing and security model for local accounts” is not set to “Classic - local users authenticate as themselves”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  ForceGuest

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Sharing and security model for local accounts” to “Classic - local users authenticate as themselves”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-174r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3378'
  tag rid: 'SV-29267r1_rule'
  tag gtitle: 'Sharing and Security Model for Local Accounts'
  tag fix_id: 'F-134r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
