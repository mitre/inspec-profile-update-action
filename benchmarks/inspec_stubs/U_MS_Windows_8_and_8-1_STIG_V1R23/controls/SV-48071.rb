control 'SV-48071' do
  title 'Network shares that can be accessed anonymously must not be allowed.'
  desc 'Anonymous access to network shares provides the potential for gaining unauthorized system access by network users.  This could lead to the exposure or corruption of sensitive data.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "Network access: Shares that can be accessed anonymously" includes any entries, this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: NullSessionShares

Value Type: REG_MULTI_SZ
Value: (Blank)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Shares that can be accessed anonymously" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44810r1_chk'
  tag severity: 'high'
  tag gid: 'V-3340'
  tag rid: 'SV-48071r1_rule'
  tag stig_id: 'WN08-SO-000059'
  tag gtitle: 'Anonymous Access to Network Shares'
  tag fix_id: 'F-41209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
