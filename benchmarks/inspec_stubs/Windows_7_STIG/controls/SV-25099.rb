control 'SV-25099' do
  title 'Named pipes and shares can be accessed anonymously.'
  desc 'This is a Category 1 finding because of the potential for gaining unauthorized system access. 

Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  

When this setting is disabled, network shares can be accessed by any network user.  This could lead to the exposure or corruption of sensitive data.

This setting configures Windows to restrict anonymous access to only those shares and pipes listed in “Network Access: Named Pipes that can be accessed anonymously”.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Restrict anonymous access to Named Pipes and Shares” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  RestrictNullSessAccess

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Restrict anonymous access to Named Pipes and Shares” to “Enabled”.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-3114r1_chk'
  tag severity: 'high'
  tag gid: 'V-6834'
  tag rid: 'SV-25099r1_rule'
  tag gtitle: 'Anonymous Access to Named Pipes and Shares'
  tag fix_id: 'F-6521r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
