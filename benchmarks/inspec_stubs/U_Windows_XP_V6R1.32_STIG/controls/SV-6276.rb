control 'SV-6276' do
  title 'Unauthorized shares can be accessed anonymously.'
  desc 'This is a Category 1 finding because the potential for gaining unauthorized system access. Any shares listed can be accessed by any network user.  This could lead to the exposure or corruption of sensitive data.  Enabling this setting is very dangerous.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Shares that can be accessed anonymously” includes entries except “DFS$ and COMCFG”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  NullSessionShares

Value Type:  REG_MULTI_SZ
Value:  as defined in policy above'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Shares that can be accessed anonymously” as defined in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-158r1_chk'
  tag severity: 'high'
  tag gid: 'V-3340'
  tag rid: 'SV-6276r1_rule'
  tag gtitle: 'Anonymous Access to Network Shares'
  tag fix_id: 'F-125r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
