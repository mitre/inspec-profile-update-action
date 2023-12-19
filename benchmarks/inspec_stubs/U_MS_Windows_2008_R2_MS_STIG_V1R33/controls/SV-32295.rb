control 'SV-32295' do
  title 'Users will be forcibly disconnected when their logon hours expire.'
  desc 'Users should not be permitted to remain logged on to the network after they have exceeded their permitted logon hours.  In many cases, this indicates that a user forgot to log off before leaving for the day.  However, it may also indicate that a user is attempting unauthorized access at a time when the system may be less closely monitored.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for “Microsoft Network Server: Disconnect Clients When Logon Hours Expire” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  EnableForcedLogoff

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Server: Disconnect Clients When Logon Hours Expire” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32720r1_chk'
  tag severity: 'low'
  tag gid: 'V-1136'
  tag rid: 'SV-32295r1_rule'
  tag gtitle: 'Forcibly Disconnect when Logon Hours Expire'
  tag fix_id: 'F-6572r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
