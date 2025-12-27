control 'SV-48080' do
  title 'The system must be configured to use the Classic security model.'
  desc 'Windows includes two network-sharing security models - Classic and Guest only. With the Classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Network access: Sharing and security model for local accounts" is not set to "Classic - local users authenticate as themselves", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: ForceGuest

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3378'
  tag rid: 'SV-48080r1_rule'
  tag stig_id: 'WN08-SO-000060'
  tag gtitle: 'Sharing and Security Model for Local Accounts'
  tag fix_id: 'F-41218r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
