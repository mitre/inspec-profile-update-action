control 'SV-32317' do
  title 'Network shares that can be accessed anonymously will not be allowed.'
  desc 'This is a Category 1 finding because the potential for gaining unauthorized system access. Any shares listed can be accessed by any network user.  This could lead to the exposure or corruption of sensitive data.  Enabling this setting is very dangerous.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “Network access: Shares that can be accessed anonymously” includes any entries, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  NullSessionShares

Value Type:  REG_MULTI_SZ
Value:  (Blank)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Shares that can be accessed anonymously” to be defined but containing no entries (Blank).'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32729r1_chk'
  tag severity: 'high'
  tag gid: 'V-3340'
  tag rid: 'SV-32317r1_rule'
  tag gtitle: 'Anonymous Access to Network Shares'
  tag fix_id: 'F-28819r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
